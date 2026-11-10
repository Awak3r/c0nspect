package web

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"

	"conspect/internal/render"
)

func assetTestRequest(handler http.Handler, method, target string, headers map[string]string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, target, nil)
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func assetTestHandler(t *testing.T) http.Handler {
	t.Helper()
	app, err := New(nil, Config{BaseURL: "http://localhost", Secret: bytes.Repeat([]byte{1}, 32), DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	return app.Handler()
}

func TestStaticAssetsVersionedAndLegacy(t *testing.T) {
	handler := assetTestHandler(t)
	for _, tc := range []struct {
		path, cache, contentType string
	}{
		{stylesheetURL(), immutableAssetCache, "text/css"},
		{readerAsset("reader.js"), immutableAssetCache, "text/javascript"},
		{readerAsset("katex.min.css"), immutableAssetCache, "text/css"},
		{readerAsset("fonts/KaTeX_Main-Regular.woff2"), immutableAssetCache, "font/woff2"},
		{"/assets/app.css", "public, no-cache", "text/css"},
		{"/assets/app.css?v=old", "public, no-cache", "text/css"},
		{stylesheetURL() + "&v=wrong", "public, no-cache", "text/css"},
		{"/assets/app.css?v=%zz", "public, no-cache", "text/css"},
		{"/assets/reader/reader.js", "public, no-cache", "text/javascript"},
		{readerAsset("LICENSE-KaTeX"), immutableAssetCache, "text/plain"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			r := assetTestRequest(handler, "GET", tc.path, nil)
			if r.Code != 200 || r.Body.Len() == 0 || r.Header().Get("Cache-Control") != tc.cache || !strings.HasPrefix(r.Header().Get("Content-Type"), tc.contentType) {
				t.Fatalf("status=%d headers=%v bytes=%d", r.Code, r.Header(), r.Body.Len())
			}
			if !strings.Contains(r.Header().Get("Vary"), "Accept-Encoding") || r.Header().Get("ETag") == "" || r.Header().Get("X-Content-Type-Options") != "nosniff" {
				t.Fatalf("missing validator/security headers: %v", r.Header())
			}
		})
	}
}

func TestStaticGzipConditionalHeadAndRanges(t *testing.T) {
	handler := assetTestHandler(t)
	path := readerAsset("katex.min.js")
	plain := assetTestRequest(handler, "GET", path, nil)
	compressed := assetTestRequest(handler, "GET", path, map[string]string{"Accept-Encoding": "gzip"})
	if compressed.Code != 200 || compressed.Header().Get("Content-Encoding") != "gzip" || compressed.Body.Len() >= plain.Body.Len()/2 {
		t.Fatalf("gzip status=%d headers=%v raw=%d encoded=%d", compressed.Code, compressed.Header(), plain.Body.Len(), compressed.Body.Len())
	}
	reader, err := gzip.NewReader(bytes.NewReader(compressed.Body.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := io.ReadAll(reader)
	if err != nil || !bytes.Equal(decoded, plain.Body.Bytes()) {
		t.Fatalf("compressed data changed: %v", err)
	}
	reader.Close()
	if plain.Header().Get("ETag") == compressed.Header().Get("ETag") {
		t.Fatal("representations must have distinct strong ETags")
	}
	for _, encoding := range []string{"", "gzip"} {
		get := assetTestRequest(handler, "GET", path, map[string]string{"Accept-Encoding": encoding})
		head := assetTestRequest(handler, "HEAD", path, map[string]string{"Accept-Encoding": encoding})
		if head.Code != 200 || head.Body.Len() != 0 || head.Header().Get("Content-Length") != strconv.Itoa(get.Body.Len()) || head.Header().Get("ETag") != get.Header().Get("ETag") {
			t.Fatalf("HEAD mismatch: status=%d headers=%v bytes=%d", head.Code, head.Header(), head.Body.Len())
		}
		for _, validator := range []string{get.Header().Get("ETag"), "W/" + get.Header().Get("ETag")} {
			r := assetTestRequest(handler, "GET", path, map[string]string{"Accept-Encoding": encoding, "If-None-Match": validator})
			if r.Code != 304 || r.Body.Len() != 0 || r.Header().Get("Cache-Control") != immutableAssetCache || !strings.Contains(r.Header().Get("Vary"), "Accept-Encoding") {
				t.Fatalf("conditional GET: status=%d headers=%v bytes=%d", r.Code, r.Header(), r.Body.Len())
			}
		}
	}
	different := assetTestRequest(handler, "GET", path, map[string]string{"Accept-Encoding": "gzip", "If-None-Match": plain.Header().Get("ETag")})
	if different.Code != 200 {
		t.Fatal("identity validator incorrectly matched gzip representation")
	}
	partial := assetTestRequest(handler, "GET", path, map[string]string{"Accept-Encoding": "gzip", "Range": "bytes=0-9", "If-Range": plain.Header().Get("ETag")})
	if partial.Code != 206 || partial.Header().Get("Content-Encoding") != "" || !bytes.Equal(partial.Body.Bytes(), plain.Body.Bytes()[:10]) {
		t.Fatalf("range mismatch: status=%d headers=%v bytes=%d", partial.Code, partial.Header(), partial.Body.Len())
	}
	staleRange := assetTestRequest(handler, "GET", path, map[string]string{"Range": "bytes=0-9", "If-Range": `"old"`})
	if staleRange.Code != 200 || !bytes.Equal(staleRange.Body.Bytes(), plain.Body.Bytes()) {
		t.Fatal("stale If-Range must return full identity representation")
	}
	t.Logf("KaTeX JS: %d raw bytes, %d precompressed bytes", plain.Body.Len(), compressed.Body.Len())
}

func TestStaticEncodingNegotiation(t *testing.T) {
	handler := assetTestHandler(t)
	for _, tc := range []struct {
		header, encoding string
		status           int
	}{
		{"", "", 200}, {"br", "", 200}, {"gzip", "gzip", 200}, {"GZIP", "gzip", 200},
		{"gzip;q=0", "", 200}, {"*;q=1, gzip;q=0", "", 200}, {"*", "gzip", 200},
		{"gzip;q=0.5, identity;q=0.2", "gzip", 200}, {"gzip;q=0.2, identity;q=0.5", "", 200},
		{"gzip;q=1, gzip;q=0", "", 200}, {"gzip;q=NaN", "", 200}, {"gzip;q=2", "", 200},
		{"gzip;q=bad", "", 200}, {"gzip;q=1;bad=1", "", 200},
		{"*;q=0", "", 406}, {"identity;q=0, gzip;q=0", "", 406},
		{"identity;q=0, gzip;q=1", "gzip", 200},
	} {
		t.Run(tc.header, func(t *testing.T) {
			r := assetTestRequest(handler, "GET", readerAsset("reader.js"), map[string]string{"Accept-Encoding": tc.header})
			if r.Code != tc.status || r.Header().Get("Content-Encoding") != tc.encoding {
				t.Fatalf("status=%d encoding=%q", r.Code, r.Header().Get("Content-Encoding"))
			}
		})
	}
	font := assetTestRequest(handler, "GET", readerAsset("fonts/KaTeX_Main-Regular.woff2"), map[string]string{"Accept-Encoding": "identity;q=0, gzip"})
	if font.Code != 406 || font.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("unsupported font representation must not be cached")
	}
}

func TestStaticErrorsAndPrivatePagesNeverBecomePublic(t *testing.T) {
	handler := assetTestHandler(t)
	for _, tc := range []struct {
		method, path string
		headers      map[string]string
		status       int
	}{
		{"GET", "/assets/reader/", nil, 404}, {"HEAD", "/assets/reader/", nil, 404},
		{"GET", "/assets/reader/old/reader.js", nil, 404},
		{"GET", "/assets/reader/not-a-file", nil, 404},
		{"GET", "/assets/reader/%2e%2e/go.mod", nil, 404},
		{"POST", readerAsset("reader.js"), nil, 405},
		{"GET", readerAsset("reader.js"), map[string]string{"Range": "bytes=999999-"}, 416},
		{"GET", readerAsset("reader.js"), map[string]string{"If-Match": `"wrong"`}, 412},
		{"GET", "/login", map[string]string{"Accept-Encoding": "gzip"}, 200},
		{"GET", "/projects", nil, 303},
		{"GET", "/api/v1/notes/invalid", nil, 401},
		{"GET", "/notes/invalid/attachments/invalid", nil, 303},
	} {
		r := assetTestRequest(handler, tc.method, tc.path, tc.headers)
		if r.Code != tc.status || r.Header().Get("Cache-Control") != "no-store" || r.Header().Get("Content-Encoding") != "" {
			t.Errorf("%s %s: status=%d headers=%v", tc.method, tc.path, r.Code, r.Header())
		}
		if tc.method == "HEAD" && r.Body.Len() != 0 {
			t.Error("HEAD error returned a body")
		}
	}
}

func TestStaticReaderBundleRelativeFontsAndConcurrentAccess(t *testing.T) {
	handler := assetTestHandler(t)
	cssURL, _ := url.Parse("http://localhost" + readerAsset("katex.min.css"))
	css := assetTestRequest(handler, "GET", cssURL.String(), nil)
	for _, match := range regexp.MustCompile(`url\(([^)]+)\)`).FindAllStringSubmatch(css.Body.String(), -1) {
		reference, err := url.Parse(match[1])
		if err != nil {
			t.Fatal(err)
		}
		resolved := cssURL.ResolveReference(reference)
		if !strings.HasPrefix(resolved.Path, readerAsset("fonts/")) {
			t.Fatalf("font escaped versioned bundle: %s", resolved.Path)
		}
		r := assetTestRequest(handler, "GET", resolved.String(), nil)
		if r.Code != 200 || r.Header().Get("Cache-Control") != immutableAssetCache {
			t.Fatalf("font request: %d", r.Code)
		}
	}
	var group sync.WaitGroup
	for range 16 {
		group.Go(func() {
			for range 10 {
				r := assetTestRequest(handler, "GET", readerAsset("reader.js"), map[string]string{"Accept-Encoding": "gzip"})
				if r.Code != 200 {
					t.Errorf("concurrent response %d", r.Code)
				}
			}
		})
	}
	group.Wait()
	for _, name := range []string{"reader.js", "katex.min.js", "syntax.css"} {
		data, err := fs.ReadFile(render.Assets(), name)
		if err != nil {
			t.Fatal(err)
		}
		r := assetTestRequest(handler, "GET", readerAsset(name), nil)
		if !bytes.Equal(data, r.Body.Bytes()) {
			t.Fatalf("vendored asset changed: %s", name)
		}
	}
	// Templates themselves stay private even though their resource URLs are public.
	app, err := New(nil, Config{BaseURL: "http://localhost", Secret: bytes.Repeat([]byte{1}, 32), DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRecorder()
	app.page(r, httptest.NewRequest("GET", "/notes/test", nil).WithContext(context.Background()), 200, "reader", pageData{})
	if !strings.Contains(r.Body.String(), readerAsset("katex.min.js")) || r.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("reader template lost versioned assets or private caching policy")
	}
}
