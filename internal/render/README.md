# Safe note reader renderer

## Integration contract

```go
renderer := render.New() // reusable across concurrent requests
html, err := renderer.Render(source, func(id string) string {
    // Authorize id against THIS note before constructing a URL.
    // Return "" for missing, deleted, non-image, or other-note attachments.
    // Shared views must include their share token in the authorized URL.
    return authorizedAttachmentURL(id)
})

mux.Handle("/assets/reader/", http.StripPrefix("/assets/reader/",
    http.FileServer(http.FS(render.Assets()))))
```

The callback is request-scoped, never cached in the renderer. Image references
must be `![alt](attachment:<id>)` (including Markdown reference-style images).
IDs are 1–128 ASCII letters, digits, `-`, or `_`; they are not filenames or paths.
Resolved URLs must be local, root-relative (recommended) or relative paths, with
no scheme, host, fragment, backslashes, control characters, whitespace, or dot
path segments. Percent-encoded query parameters are supported. External URLs,
local Markdown paths, invalid IDs, empty results, and a nil callback produce
only escaped alt text, never an `img` or an empty `src` request. The renderer
never opens attachment files or makes network requests.

The parent owns templates, routing, attachment authorization, and CSP headers.
Load the four root assets in this order, using **external** scripts only:

```html
<link rel="stylesheet" href="/assets/reader/katex.min.css">
<link rel="stylesheet" href="/assets/reader/syntax.css">
<script defer src="/assets/reader/katex.min.js"></script>
<script defer src="/assets/reader/reader.js"></script>
```

Use a standards-mode document (`<!doctype html>`). `script-src 'self'` works;
no inline script, inline event handler, eval, CDN, npm, or third-party service
is needed at runtime. Permit local styles/fonts/images. KaTeX creates inline
**style attributes** for mathematical layout, so a CSP that restricts styles
must allow those (for example `style-src 'self'; style-src-attr 'unsafe-inline'`
in CSP3, or `style-src 'self' 'unsafe-inline'` for older browsers). This does not
require allowing inline scripts. A parent CSP can additionally use
`img-src 'self'; font-src 'self'; connect-src 'none'; object-src 'none'`.

## Security and behavior

- Goldmark parses GFM tables, nested/ordered lists, task lists, strikethrough,
  links, and fenced/inline code. Task markers are inert text, not form controls.
- Raw author HTML is disabled **before** a strict Bluemonday sanitizer. Only
  generated math nodes may emit `data-math`/`data-tex`; arbitrary HTML cannot
  forge them. Source and attribute values are HTML-escaped, not interpolated
  as markup. Only HTTP(S), mailto, and relative links survive sanitization;
  links get `nofollow noreferrer`.
- Custom Goldmark block/inline parsers recognize `$...$` (single-line inline)
  and `$$...$$` display math, including multiline matrices/alignments and
  display blocks in lists/quotes. They consume TeX before Markdown can change
  backslashes, underscores, ampersands, HTML-like text, or other syntax. Dollar
  escapes and code spans/fences/indented code are respected. Display block
  closing delimiters must end their line, apart from whitespace.
- Math source with delimiters is visible without JavaScript. Unclosed display
  blocks and formulas over **16 KiB** stay escaped visible source and are not
  sent to KaTeX. The browser independently enforces a 16,384 UTF-16-unit limit;
  the server's byte limit is at least as strict for valid UTF-8.
- `reader.js` processes only generated math markers, skips code, and calls
  KaTeX with `trust: false`, `throwOnError: false`, `strict: "error"`,
  `maxExpand: 1000`, and `maxSize: 20` em. Fresh macro dictionaries per formula
  prevent `\gdef` state from crossing formulas/notes. Unsupported/invalid TeX
  has visible fallback; unexpected renderer failures leave the original source
  untouched. KaTeX is a bounded browser math parser, not a full TeX engine:
  no shell execution or server-file access is performed. TeX HTML commands,
  links, and `\includegraphics` cannot create trusted markup or fetch images.
- Chroma highlights explicitly named fenced code languages, with local CSS
  classes only. Unknown/invalid languages, lexer errors, and blocks over
  **128 KiB** fall back to escaped plain code. No copy-code controls or other buttons are generated.
- No note text is sent to an external service. HTTP(S) Markdown links are
  ordinary navigation links; external images are never embedded.

## Dependencies and vendored assets

Existing Go dependencies, with no `go.mod`/`go.sum` changes:

- `github.com/yuin/goldmark` **v1.8.7**
- `github.com/microcosm-cc/bluemonday` **v1.0.27**
- `github.com/alecthomas/chroma/v2` **v2.27.0** (`github` syntax theme)

KaTeX **0.19.1**, pinned stable npm release:

- Tarball: <https://registry.npmjs.org/katex/-/katex-0.19.1.tgz>
- npm registry SHA-512 integrity (verified **before** extracting assets):
  `sha512-jG8uKntjSEcm2EpQOh0XturpPuuC9r3Sq5HLHdsFdWZT27E672SF19QEi+of0/YeOy15lDgRhKvr5614uRrEfA==`
- Unmodified `dist/katex.min.js`, `dist/katex.min.css`, and exactly the **60**
  font files referenced by that CSS (`woff2`, `woff`, `ttf`) are embedded.
  No auto-render plugin, npm dependency tree, or source maps are needed.
- KaTeX code/CSS: MIT, `static/LICENSE-KaTeX` (from the verified tarball).
- KaTeX fonts: SIL OFL **1.1**, `static/fonts/OFL.txt`, including the font
  metadata's copyright and reserved-name notices. Font binaries are unmodified.
- Chroma-generated CSS: MIT, `static/LICENSE-Chroma`.

Tests pin the JS/CSS SHA-256 hashes and verify every CSS font URL resolves
within `Assets()`. To regenerate syntax CSS from the installed pinned Chroma:

```sh
# From internal/render:
go run -mod=readonly generate_syntax.go
```

Validation from the project root:

```sh
go test -mod=readonly ./internal/render
go test -mod=readonly -race ./internal/render
node --test internal/render/testdata/reader.test.cjs
```

The Go tests also run the dependency-free Node tests when `node` is installed;
otherwise that one test is explicitly skipped. Node is a development/test tool,
not a production requirement. The Node suite uses VM/DOM stubs for reader
behavior and the real vendored KaTeX parser for rendering/security tests; it is
not a full browser layout test. Optional Go fuzzing exercises the same rendered
HTML security assertions without network access.
