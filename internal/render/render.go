// Package render converts untrusted note Markdown into safe reader HTML.
package render

import (
	"bytes"
	"fmt"
	"html"
	"html/template"
	"net/url"
	"regexp"
	"strings"
	"unicode"

	"github.com/microcosm-cc/bluemonday"
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/extension"
	extast "github.com/yuin/goldmark/extension/ast"
	"github.com/yuin/goldmark/parser"
	"github.com/yuin/goldmark/renderer"
	"github.com/yuin/goldmark/util"
)

// Renderer is safe to reuse concurrently. Resolvers are scoped to one Render call.
type Renderer struct {
	policy *bluemonday.Policy
}

// New constructs a renderer with raw author HTML disabled and a strict allowlist.
func New() *Renderer {
	p := bluemonday.NewPolicy()
	p.AllowElements("p", "br", "hr", "strong", "em", "del", "blockquote",
		"ul", "ol", "li", "h1", "h2", "h3", "h4", "h5", "h6", "pre", "code",
		"table", "thead", "tbody", "tr", "th", "td", "a", "img", "span", "div")
	p.AllowAttrs("href", "title").OnElements("a")
	p.AllowURLSchemes("http", "https", "mailto")
	p.AllowRelativeURLs(true)
	p.RequireParseableURLs(true)
	p.RequireNoFollowOnLinks(true)
	p.RequireNoReferrerOnLinks(true)
	p.AllowAttrs("start").Matching(regexp.MustCompile(`^[0-9]{1,9}$`)).OnElements("ol")
	p.AllowAttrs("align").Matching(regexp.MustCompile(`^(left|center|right)$`)).OnElements("th", "td")
	p.AllowAttrs("class").Matching(regexp.MustCompile(`^(syntax-chroma|math-source)$`)).OnElements("pre")
	p.AllowAttrs("class").Matching(regexp.MustCompile(`^language-[a-zA-Z0-9_+-]{1,64}$`)).OnElements("code")
	p.AllowAttrs("class").Matching(regexp.MustCompile(`^(syntax-[a-z0-9]+|math math-inline|math math-display|task-marker)$`)).OnElements("span")
	p.AllowAttrs("class").Matching(regexp.MustCompile(`^math math-display$`)).OnElements("div")
	// Only our node renderer can emit these attributes: Goldmark's unsafe HTML
	// and attribute parsing options are deliberately never enabled.
	p.AllowAttrs("data-math").Matching(regexp.MustCompile(`^(inline|block)$`)).OnElements("span", "div")
	p.AllowAttrs("data-tex").OnElements("span", "div")
	p.AllowAttrs("src", "alt", "title").OnElements("img")
	p.AllowAttrs("loading").Matching(regexp.MustCompile(`^lazy$`)).OnElements("img")
	p.AllowAttrs("decoding").Matching(regexp.MustCompile(`^async$`)).OnElements("img")
	p.AllowAttrs("referrerpolicy").Matching(regexp.MustCompile(`^no-referrer$`)).OnElements("img")
	return &Renderer{policy: p}
}

// Render renders Markdown without fetching resources or reading note attachments.
// Only attachment:<id> images are resolved. The caller must authorize the ID for
// the current note and return a local URL (including a share token when needed),
// or an empty string to reject it. IDs are URL-safe alphanumeric, '-' or '_'
// tokens of at most 128 bytes. A nil resolver rejects all images.
func (r *Renderer) Render(source string, attachmentURL func(id string) string) (template.HTML, error) {
	// Per-call configuration keeps the authorization callback out of shared state.
	md := goldmark.New(
		goldmark.WithExtensions(extension.Linkify, extension.Strikethrough, extension.TaskList,
			extension.NewTable(extension.WithTableCellAlignMethod(extension.TableCellAlignAttribute))),
		goldmark.WithParserOptions(
			parser.WithInlineParsers(util.Prioritized(mathInlineParser{}, 150)),
			parser.WithBlockParsers(util.Prioritized(mathBlockParser{}, 850))),
		goldmark.WithRendererOptions(renderer.WithNodeRenderers(
			util.Prioritized(&nodeRenderer{attachmentURL: attachmentURL}, 100))),
	)
	var output bytes.Buffer
	if err := md.Convert([]byte(source), &output); err != nil {
		return "", fmt.Errorf("render Markdown: %w", err)
	}
	return template.HTML(r.policy.SanitizeBytes(output.Bytes())), nil // #nosec G203 -- sanitized allowlisted HTML
}

type nodeRenderer struct {
	attachmentURL func(string) string
}

func (r *nodeRenderer) RegisterFuncs(reg renderer.NodeRendererFuncRegisterer) {
	reg.Register(kindMathInline, r.renderInlineMath)
	reg.Register(kindMathBlock, r.renderBlockMath)
	reg.Register(ast.KindImage, r.renderImage)
	reg.Register(ast.KindFencedCodeBlock, r.renderCodeBlock)
	reg.Register(extast.KindTaskCheckBox, r.renderTaskMarker)
}

func (r *nodeRenderer) renderImage(w util.BufWriter, source []byte, node ast.Node, entering bool) (ast.WalkStatus, error) {
	if !entering {
		return ast.WalkContinue, nil
	}
	n := node.(*ast.Image)
	alt := html.EscapeString(markdownText(n.Text(source)))
	id, ok := attachmentID(string(n.Destination))
	var destination string
	if ok && r.attachmentURL != nil {
		destination = r.attachmentURL(id)
	}
	if !safeAttachmentURL(destination) {
		_, _ = w.WriteString(alt)
		return ast.WalkSkipChildren, nil
	}
	_, _ = fmt.Fprintf(w, `<img src="%s" alt="%s"`, html.EscapeString(destination), alt)
	if len(n.Title) != 0 {
		_, _ = fmt.Fprintf(w, ` title="%s"`, html.EscapeString(markdownText(n.Title)))
	}
	_, _ = w.WriteString(` loading="lazy" decoding="async" referrerpolicy="no-referrer">`)
	return ast.WalkSkipChildren, nil
}

func markdownText(value []byte) string {
	return html.UnescapeString(string(util.UnescapePunctuations(value)))
}

func attachmentID(destination string) (string, bool) {
	id, ok := strings.CutPrefix(destination, "attachment:")
	if !ok || len(id) == 0 || len(id) > 128 {
		return "", false
	}
	for _, c := range []byte(id) {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return "", false
		}
	}
	return id, true
}

func safeAttachmentURL(value string) bool {
	if value == "" || strings.ContainsAny(value, `\`) || strings.IndexFunc(value, func(c rune) bool {
		return unicode.IsControl(c) || unicode.IsSpace(c)
	}) >= 0 {
		return false
	}
	u, err := url.Parse(value)
	if err != nil || u.IsAbs() || u.Host != "" || u.User != nil || u.Opaque != "" || u.Fragment != "" || u.Path == "" {
		return false
	}
	if strings.HasPrefix(u.Path, "//") || strings.ContainsAny(u.Path, `\`) || strings.IndexFunc(u.Path, unicode.IsControl) >= 0 {
		return false
	}
	for _, part := range strings.Split(u.Path, "/") {
		if part == "." || part == ".." {
			return false
		}
	}
	return true
}

func (r *nodeRenderer) renderTaskMarker(w util.BufWriter, _ []byte, node ast.Node, entering bool) (ast.WalkStatus, error) {
	if entering {
		marker := "☐"
		if node.(*extast.TaskCheckBox).IsChecked {
			marker = "☑"
		}
		_, _ = fmt.Fprintf(w, `<span class="task-marker">%s</span> `, marker)
	}
	return ast.WalkContinue, nil
}
