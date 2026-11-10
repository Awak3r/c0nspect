package render

import (
	"container/list"
	"crypto/sha256"
	"sync"

	"golang.org/x/sync/singleflight"
)

const (
	maxHighlightCacheBytes   = 8 << 20
	maxHighlightCacheEntries = 512
)

type highlightEntry struct {
	key  [32]byte
	html string
}

type highlightResult struct {
	html string
	ok   bool
}

// Only code-fragment HTML is retained, never attachment URLs or complete pages.
// Each Renderer owns its cache; formatter/policy changes require a new process.
// Payload bytes and entry count are both bounded (list/map metadata is additional).
type highlightCache struct {
	mu                    sync.Mutex
	entries               map[[32]byte]*list.Element
	lru                   list.List
	bytes, limit, maxSize int
	flights               singleflight.Group
}

func newHighlightCache(limit, maxSize int) *highlightCache {
	return &highlightCache{entries: make(map[[32]byte]*list.Element), limit: limit, maxSize: maxSize}
}

func (c *highlightCache) get(key [32]byte) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	if !ok {
		return "", false
	}
	c.lru.MoveToFront(entry)
	return entry.Value.(highlightEntry).html, true
}

func (c *highlightCache) store(key [32]byte, html string) {
	size := len(key) + len(html)
	if size > c.limit {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.entries[key]; exists {
		return
	}
	for c.bytes+size > c.limit || len(c.entries) >= c.maxSize {
		oldest := c.lru.Back()
		entry := oldest.Value.(highlightEntry)
		c.bytes -= len(entry.key) + len(entry.html)
		delete(c.entries, entry.key)
		c.lru.Remove(oldest)
	}
	c.entries[key] = c.lru.PushFront(highlightEntry{key: key, html: html})
	c.bytes += size
}

func (c *highlightCache) getOrCompute(language, code string, compute func() (string, bool)) (string, bool) {
	if c == nil || c.limit <= 0 || c.maxSize <= 0 {
		return compute()
	}
	digest := sha256.New()
	digest.Write([]byte(language))
	digest.Write([]byte{0})
	digest.Write([]byte(code))
	var key [32]byte
	digest.Sum(key[:0])
	if html, ok := c.get(key); ok {
		return html, true
	}
	result, _, _ := c.flights.Do(string(key[:]), func() (any, error) {
		if html, ok := c.get(key); ok {
			return highlightResult{html: html, ok: true}, nil
		}
		html, ok := compute()
		if ok {
			c.store(key, html)
		}
		return highlightResult{html: html, ok: ok}, nil
	})
	highlighted := result.(highlightResult)
	return highlighted.html, highlighted.ok
}
