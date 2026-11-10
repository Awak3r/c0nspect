package web

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"fmt"
	"io/fs"
	"mime"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"conspect/internal/render"
)

const immutableAssetCache = "public, max-age=31536000, immutable"

type assetRepresentation struct {
	body []byte
	etag string
}

type staticAsset struct {
	identity, gzip assetRepresentation
	contentType    string
}

type assetRoute struct {
	asset     *staticAsset
	immutable bool
}

type staticAssets struct {
	paths        map[string]assetRoute
	readerPrefix string
}

// The embedded files, compressed representations and validators are prepared
// once per process, not once per App (tests and secret rotation create many).
var publicAssets = prepareStaticAssets()

func prepareStaticAssets() staticAssets {
	assets := render.Assets()
	reader := make(map[string]*staticAsset)
	bundle := sha256.New()
	// WalkDir's lexical order makes the bundle digest deterministic. Hash names
	// as well as bytes so relative font references share the bundle's lifetime.
	err := fs.WalkDir(assets, ".", func(name string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		body, err := fs.ReadFile(assets, name)
		if err != nil {
			return err
		}
		digest := sha256.Sum256(body)
		fmt.Fprintf(bundle, "%s\x00%x\n", name, digest)
		reader[name] = prepareStaticAsset(name, body)
		return nil
	})
	if err != nil {
		panic(fmt.Errorf("prepare embedded reader assets: %w", err))
	}
	result := staticAssets{
		paths:        make(map[string]assetRoute, 2*len(reader)+1),
		readerPrefix: fmt.Sprintf("/assets/reader/%x/", bundle.Sum(nil)),
	}
	for name, asset := range reader {
		result.paths["/assets/reader/"+name] = assetRoute{asset: asset}
		result.paths[result.readerPrefix+name] = assetRoute{asset: asset, immutable: true}
	}
	result.paths["/assets/app.css"] = assetRoute{asset: prepareStaticAsset("app.css", []byte(appCSS))}
	return result
}

func prepareStaticAsset(name string, body []byte) *staticAsset {
	contentType := mime.TypeByExtension(path.Ext(name))
	switch path.Ext(name) {
	case ".css":
		contentType = "text/css; charset=utf-8"
	case ".js":
		contentType = "text/javascript; charset=utf-8"
	case ".woff":
		contentType = "font/woff"
	case ".woff2":
		contentType = "font/woff2"
	case ".ttf":
		contentType = "font/ttf"
	case ".txt":
		contentType = "text/plain; charset=utf-8"
	}
	if strings.HasPrefix(path.Base(name), "LICENSE-") {
		contentType = "text/plain; charset=utf-8"
	}
	if contentType == "" {
		contentType = http.DetectContentType(body)
	}
	asset := &staticAsset{identity: prepareRepresentation(body), contentType: contentType}
	if strings.HasPrefix(contentType, "text/") || contentType == "application/javascript" {
		var compressed bytes.Buffer
		writer, err := gzip.NewWriterLevel(&compressed, gzip.BestCompression)
		if err != nil {
			panic(err)
		}
		if _, err := writer.Write(body); err != nil {
			panic(err)
		}
		if err := writer.Close(); err != nil {
			panic(err)
		}
		asset.gzip = prepareRepresentation(compressed.Bytes())
	}
	return asset
}

func prepareRepresentation(body []byte) assetRepresentation {
	return assetRepresentation{body: body, etag: fmt.Sprintf(`"%x"`, sha256.Sum256(body))}
}

func readerAsset(name string) string { return publicAssets.readerPrefix + name }

func serveStaticAsset(w http.ResponseWriter, r *http.Request) {
	w = staticResponseWriter{ResponseWriter: w, head: r.Method == http.MethodHead}
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// Exact matches only: no path cleaning, filesystem fallback or directory index.
	route, ok := publicAssets.paths[r.URL.Path]
	if !ok {
		http.NotFound(w, r)
		return
	}
	h := w.Header()
	h.Add("Vary", "Accept-Encoding")
	gzipQ, identityQ := assetEncodingQuality(strings.Join(r.Header.Values("Accept-Encoding"), ","))
	representation := route.asset.identity
	// Identity ranges avoid encoded-byte offsets for ordinary resumable requests.
	if route.asset.gzip.body != nil && gzipQ > 0 && (identityQ == 0 || gzipQ >= identityQ && r.Header.Get("Range") == "") {
		representation = route.asset.gzip
		h.Set("Content-Encoding", "gzip")
	} else if identityQ == 0 {
		http.Error(w, "no acceptable asset encoding", http.StatusNotAcceptable)
		return
	}
	cache := "public, no-cache"
	if route.immutable {
		cache = immutableAssetCache
	} else if r.URL.Path == "/assets/app.css" {
		query, err := url.ParseQuery(r.URL.RawQuery)
		if err == nil && len(query["v"]) == 1 && query.Get("v") == strings.TrimPrefix(stylesheetURL(), "/assets/app.css?v=") {
			cache = immutableAssetCache
		}
	}
	h.Set("Cache-Control", cache)
	h.Set("Content-Type", route.asset.contentType)
	h.Set("ETag", representation.etag)
	// ServeContent deliberately doesn't infer length for encoded responses.
	// These are already encoded bytes, so their exact length is known.
	h.Set("Content-Length", strconv.Itoa(len(representation.body)))
	http.ServeContent(w, r, path.Base(r.URL.Path), time.Time{}, bytes.NewReader(representation.body))
}

// ServeContent clears cache headers on errors by default (configurable through
// GODEBUG). Always keep errors non-cacheable, including 412/416, in either mode.
type staticResponseWriter struct {
	http.ResponseWriter
	head bool
}

func (w staticResponseWriter) WriteHeader(status int) {
	if status >= 400 {
		h := w.Header()
		h.Set("Cache-Control", "no-store")
		for _, name := range []string{"ETag", "Content-Encoding", "Content-Length"} {
			h.Del(name)
		}
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w staticResponseWriter) Write(body []byte) (int, error) {
	if w.head {
		return len(body), nil
	}
	return w.ResponseWriter.Write(body)
}

// Explicit codings override wildcard, including explicit q=0 exclusions.
// Identity is acceptable by default unless identity;q=0 or an unoverridden *;q=0.
func assetEncodingQuality(header string) (gzipQ, identityQ float64) {
	qualities := make(map[string]float64)
	for _, item := range strings.Split(header, ",") {
		parts := strings.Split(item, ";")
		coding := strings.ToLower(strings.TrimSpace(parts[0]))
		if coding != "gzip" && coding != "identity" && coding != "*" {
			continue
		}
		quality := 1.0
		for i, parameter := range parts[1:] {
			key, value, ok := strings.Cut(strings.TrimSpace(parameter), "=")
			q, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
			if i != 0 || !ok || !strings.EqualFold(key, "q") || err != nil || !(q >= 0 && q <= 1) {
				quality = 0
				break
			}
			quality = q
		}
		// Conflicting duplicate entries are conservatively resolved to the lower q.
		if previous, ok := qualities[coding]; !ok || quality < previous {
			qualities[coding] = quality
		}
	}
	gzipQ = qualities["*"]
	if q, ok := qualities["gzip"]; ok {
		gzipQ = q
	}
	identityQ = 1
	if q, ok := qualities["identity"]; ok {
		identityQ = q
	} else if q, ok := qualities["*"]; ok && q == 0 {
		identityQ = 0
	}
	return gzipQ, identityQ
}
