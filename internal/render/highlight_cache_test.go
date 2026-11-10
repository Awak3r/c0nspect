package render

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func TestHighlightCacheBoundsAndLRU(t *testing.T) {
	cache := newHighlightCache(256, 2)
	calls := make(map[string]int)
	get := func(key string) {
		t.Helper()
		html, ok := cache.getOrCompute("go", key, func() (string, bool) {
			calls[key]++
			return strings.Repeat(key, 64), true
		})
		if !ok || html != strings.Repeat(key, 64) {
			t.Fatal("cache changed highlighted output")
		}
		if cache.bytes > cache.limit || len(cache.entries) > cache.maxSize {
			t.Fatalf("cache exceeded bounds: bytes=%d entries=%d", cache.bytes, len(cache.entries))
		}
	}
	get("a")
	get("b")
	get("a") // Keep a and evict b when c is inserted.
	get("c")
	get("a")
	get("b")
	if calls["a"] != 1 || calls["b"] != 2 || calls["c"] != 1 {
		t.Fatalf("not LRU: %v", calls)
	}
	byteBound := newHighlightCache(150, 100)
	for i := range 100 {
		byteBound.getOrCompute("go", fmt.Sprint(i), func() (string, bool) { return strings.Repeat("x", 64), true })
		if byteBound.bytes > 150 || len(byteBound.entries) != 1 {
			t.Fatal("payload budget did not evict independently of entry count")
		}
	}
}

func TestHighlightCacheKeysFailuresAndOversize(t *testing.T) {
	cache := newHighlightCache(1024, 8)
	calls := 0
	compute := func() (string, bool) { calls++; return "highlighted", true }
	for _, pair := range [][2]string{{"go", "same"}, {"python", "same"}, {"go", "different"}, {"go", "same"}} {
		cache.getOrCompute(pair[0], pair[1], compute)
	}
	if calls != 3 {
		t.Fatalf("language/source keys collide: %d calls", calls)
	}
	for _, tc := range []struct {
		limit int
		ok    bool
	}{
		{64, true}, {1024, false}, {0, true},
	} {
		cache := newHighlightCache(tc.limit, 8)
		calls := 0
		for range 2 {
			_, ok := cache.getOrCompute("go", "source", func() (string, bool) {
				calls++
				return strings.Repeat("x", 65), tc.ok
			})
			if ok != tc.ok {
				t.Fatal("computation result was changed")
			}
		}
		if calls != 2 || len(cache.entries) != 0 {
			t.Fatalf("failed/oversized/disabled entry was cached: calls=%d entries=%d", calls, len(cache.entries))
		}
	}
}

func TestHighlightCacheConcurrentDuplicateWork(t *testing.T) {
	cache := newHighlightCache(1024, 8)
	var calls atomic.Int32
	var group sync.WaitGroup
	start := make(chan struct{})
	for range 32 {
		group.Go(func() {
			<-start
			for range 10 {
				html, ok := cache.getOrCompute("go", "same source", func() (string, bool) {
					calls.Add(1)
					return "same highlighted HTML", true
				})
				if !ok || html != "same highlighted HTML" {
					t.Error("concurrent render changed output")
				}
			}
		})
	}
	close(start)
	group.Wait()
	if calls.Load() != 1 {
		t.Fatalf("duplicate computation: %d", calls.Load())
	}
}

func TestHighlightBudgetIsPerDocumentAndCacheIndependent(t *testing.T) {
	renderer := New()
	block := "```go\n" + strings.Repeat("var x = 1\n", 6000) + "```\n\n"
	source := strings.Repeat(block, 3)
	first, err := renderer.Render(source, nil)
	if err != nil {
		t.Fatal(err)
	}
	blocks := regexp.MustCompile(`(?s)<pre\b.*?</pre>`).FindAllString(string(first), -1)
	if len(blocks) != 3 || !strings.Contains(blocks[0], "<span") || !strings.Contains(blocks[1], "<span") || strings.Contains(blocks[2], "<span") {
		t.Fatal("expected two highlighted blocks followed by an intact plain-code fallback")
	}
	if !strings.Contains(blocks[2], "var x = 1") {
		t.Fatal("budget fallback lost code contents")
	}
	second, err := renderer.Render(source, nil)
	if err != nil || second != first {
		t.Fatalf("cache hits changed the document budget/output: %v", err)
	}
	third, err := renderer.Render(block, nil)
	if err != nil || !strings.Contains(string(third), "<span") {
		t.Fatalf("document budget leaked between calls: %v", err)
	}
}

func TestHighlightCacheDoesNotCacheAttachmentAuthorization(t *testing.T) {
	renderer := New()
	source := "```html\n<script>alert(1)</script>\n```\n\n![image](attachment:image1)"
	for _, prefix := range []string{"/notes/a/attachments/", "/s/new-share/attachments/", ""} {
		output, err := renderer.Render(source, func(id string) string {
			if prefix == "" {
				return ""
			}
			return prefix + id
		})
		if err != nil || strings.Contains(string(output), "<script>") {
			t.Fatalf("sanitization was bypassed: %v", err)
		}
		if prefix == "" {
			if strings.Contains(string(output), "<img") {
				t.Fatal("revoked attachment was reused from cache")
			}
		} else if !strings.Contains(string(output), `src="`+prefix+"image1"+`"`) {
			t.Fatal("attachment resolver was not reevaluated")
		}
		if prefix != "/notes/a/attachments/" && strings.Contains(string(output), "/notes/a/attachments/") {
			t.Fatal("owner attachment URL leaked into shared/canceled resolution")
		}
	}
}

func BenchmarkRenderHighlightedCode(b *testing.B) {
	code := strings.Repeat("var value = 123 // synthetic benchmark\n", 1772)
	source := "```go\n" + code + "```\n"
	for _, cached := range []bool{false, true} {
		b.Run(fmt.Sprintf("cached=%t", cached), func(b *testing.B) {
			renderer := New()
			if !cached {
				renderer.highlights = newHighlightCache(0, 0)
			}
			if _, err := renderer.Render(source, nil); err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.SetBytes(int64(len(code)))
			b.ResetTimer()
			for range b.N {
				if _, err := renderer.Render(source, nil); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
