package render

import (
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/alecthomas/chroma/v2"
	"github.com/alecthomas/chroma/v2/lexers"
	"golang.org/x/net/html"
)

func rendered(t testing.TB, r *Renderer, source string, resolver func(string) string) *html.Node {
	t.Helper()
	output, err := r.Render(source, resolver)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := html.Parse(strings.NewReader(string(output)))
	if err != nil {
		t.Fatal(err)
	}
	assertInert(t, doc)
	return doc
}

func walk(node *html.Node, visit func(*html.Node)) {
	visit(node)
	for child := node.FirstChild; child != nil; child = child.NextSibling {
		walk(child, visit)
	}
}

func elements(node *html.Node, tag string) []*html.Node {
	var found []*html.Node
	walk(node, func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == tag {
			found = append(found, n)
		}
	})
	return found
}

func attribute(node *html.Node, name string) string {
	for _, a := range node.Attr {
		if a.Key == name {
			return a.Val
		}
	}
	return ""
}

func textContent(node *html.Node) string {
	var content strings.Builder
	walk(node, func(n *html.Node) {
		if n.Type == html.TextNode {
			content.WriteString(n.Data)
		}
	})
	return content.String()
}

func formulas(node *html.Node) []*html.Node {
	var found []*html.Node
	walk(node, func(n *html.Node) {
		if attribute(n, "data-math") != "" {
			found = append(found, n)
		}
	})
	return found
}

func assertInert(t testing.TB, doc *html.Node) {
	t.Helper()
	walk(doc, func(n *html.Node) {
		if n.Type != html.ElementNode {
			return
		}
		switch n.Data {
		case "script", "style", "iframe", "object", "embed", "svg", "math", "button", "form", "input", "video", "audio", "link", "meta":
			t.Errorf("active/unexpected element %q", n.Data)
		}
		for _, a := range n.Attr {
			if strings.HasPrefix(a.Key, "on") || a.Key == "style" || a.Key == "srcset" {
				t.Errorf("unsafe attribute %q on %s", a.Key, n.Data)
			}
			if a.Key == "href" || a.Key == "src" {
				u, err := url.Parse(a.Val)
				if err != nil || u.Scheme != "" && u.Scheme != "http" && u.Scheme != "https" && u.Scheme != "mailto" {
					t.Errorf("unsafe URL %q", a.Val)
				}
			}
		}
		if n.Data == "img" && !safeAttachmentURL(attribute(n, "src")) {
			t.Errorf("non-local image URL: %q", attribute(n, "src"))
		}
	})
}

func TestMarkdown(t *testing.T) {
	doc := rendered(t, New(), "# Reader\n\n**bold** and *emphasis* and ~~deleted~~\n\n"+
		"| Left | Right |\n| :--- | ---: |\n| a | b |\n\n"+
		"- first\n  - nested\n- [x] done\n- [ ] pending\n\n3. third\n4. fourth\n\n"+
		"[safe](https://example.test/page?q=a&b=c) [mail](mailto:reader@example.test) [local](/notes/one) [anchor](#reader)", nil)
	for _, tag := range []string{"h1", "strong", "em", "del", "table", "thead", "tbody", "ul", "ol", "li"} {
		if len(elements(doc, tag)) == 0 {
			t.Errorf("missing GFM element %s", tag)
		}
	}
	if attribute(elements(doc, "ol")[0], "start") != "3" {
		t.Error("ordered list start was lost")
	}
	if attribute(elements(doc, "th")[1], "align") != "right" {
		t.Error("table alignment was lost")
	}
	links := elements(doc, "a")
	if len(links) != 4 || attribute(links[0], "href") != "https://example.test/page?q=a&b=c" {
		t.Fatalf("safe links lost: %d links", len(links))
	}
	if !strings.Contains(attribute(links[0], "rel"), "noreferrer") {
		t.Error("external links need noreferrer")
	}
	if !strings.Contains(textContent(doc), "☑") || !strings.Contains(textContent(doc), "☐") {
		t.Error("task list markers missing")
	}
}

func TestMathPreservesSource(t *testing.T) {
	inline := `\frac{a_b}{c^2} + \text{**literal**} + [x](https://evil.test) + <img src=x onerror=alert(1)>`
	block := "\n\\begin{pmatrix}\na & b \\\\\nc & d\n\\end{pmatrix}\n"
	doc := rendered(t, New(), "Before $"+inline+"$ after.\n\n$$"+block+"$$\n\nFollowing paragraph.", nil)
	math := formulas(doc)
	if len(math) != 2 {
		t.Fatalf("got %d formulas, want 2", len(math))
	}
	for i, expected := range []string{inline, block} {
		if got := attribute(math[i], "data-tex"); got != expected {
			t.Errorf("formula %d changed: got %q, want %q", i, got, expected)
		}
		delimiter := "$"
		if i == 1 {
			delimiter = "$$"
		}
		if textContent(math[i]) != delimiter+expected+delimiter {
			t.Errorf("source fallback changed: %q", textContent(math[i]))
		}
	}
	if math[1].Data != "div" || attribute(math[1], "data-math") != "block" {
		t.Error("display formula is not a block")
	}
	if len(elements(doc, "img"))+len(elements(doc, "a"))+len(elements(doc, "strong")) != 0 {
		t.Error("Markdown/HTML inside formulas was interpreted")
	}
	if !strings.Contains(textContent(doc), "Following paragraph.") {
		t.Error("block consumed following paragraph")
	}
}

func TestMathDelimiters(t *testing.T) {
	cases := []struct {
		name, source, tex string
		count             int
	}{
		{"escaped", `\$x\$`, "", 0},
		{"escaped price", `\$5 and $x$`, "x", 1},
		{"escaped closing dollar", `$a+\$b$`, `a+\$b`, 1},
		{"even backslashes", `\\$x$`, "x", 1},
		{"odd backslashes", `\\\$x\$`, "", 0},
		{"triple dollars", `$$$x$$$`, "", 0},
		{"unclosed inline", `$x`, "", 0},
		{"unclosed block", "$$\nx_1\n**literal**", "", 0},
		{"single line display", "$$x$$\n\nFollowing", "x", 1},
		{"inline display", "Before $$x$$ after", "x", 1},
		{"block in quote", "> $$\n> x_1\n> $$\n\nAfter", "\nx_1\n", 1},
		{"block in list", "- $$\n  x_1\n  $$\n\nAfter", "\nx_1\n", 1},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			doc := rendered(t, New(), tt.source, nil)
			math := formulas(doc)
			if len(math) != tt.count {
				t.Fatalf("got %d formulas, want %d: %q", len(math), tt.count, textContent(doc))
			}
			if tt.count != 0 && attribute(math[0], "data-tex") != tt.tex {
				t.Errorf("got source %q, want %q", attribute(math[0], "data-tex"), tt.tex)
			}
		})
	}
}

func TestMathSkipsCode(t *testing.T) {
	source := "`$inline$` and ``$$inline display$$`` and `multiline\n$x$`\n\n" +
		"```go\n// $fenced$\nconst formula = \"$$display$$\"\n```\n\n" +
		"~~~text\n$$\nnot math\n$$\n~~~\n\n" +
		"    $$\n    indented code\n    $$\n\nOutside $x_1$"
	doc := rendered(t, New(), source, nil)
	math := formulas(doc)
	if len(math) != 1 || attribute(math[0], "data-tex") != "x_1" {
		t.Fatalf("math parsed in code: %d formulas", len(math))
	}
	for _, code := range elements(doc, "code") {
		if len(formulas(code)) != 0 {
			t.Error("code contains a math node")
		}
	}
	if !strings.Contains(textContent(doc), "$fenced$") || !strings.Contains(textContent(doc), "$$inline display$$") {
		t.Error("code source changed")
	}
}

func TestMathAttributesCannotInjectHTML(t *testing.T) {
	tex := `\text{" onmouseover="alert(1)" data-evil="yes} </span><img src=x onerror=alert(1)> &quot; &#34; <script>bad()</script>`
	doc := rendered(t, New(), "$"+tex+"$\n\n$$"+tex+"$$", nil)
	math := formulas(doc)
	if len(math) != 2 {
		t.Fatalf("got %d formulas", len(math))
	}
	for _, n := range math {
		if attribute(n, "data-tex") != tex || attribute(n, "data-evil") != "" {
			t.Errorf("math attribute injection/source corruption: %+v", n.Attr)
		}
	}
	if len(elements(doc, "img")) != 0 {
		t.Error("math source became an image")
	}
	spoof := `<span class="math math-inline" data-math="inline" data-tex="injected">spoof</span>` +
		"\n\n" + `<div class="math math-display" data-math="block" data-tex="injected">spoof</div>`
	if math := formulas(rendered(t, New(), spoof, nil)); len(math) != 0 {
		t.Error("raw author HTML forged a trusted formula")
	}
}

func TestMathLimitsAndUnclosedFallback(t *testing.T) {
	for _, value := range []string{strings.Repeat("x", maxMathSource+1), strings.Repeat("界", maxMathSource/3+1)} {
		doc := rendered(t, New(), "$"+value+"$\n\n$$"+value+"$$", nil)
		if len(formulas(doc)) != 0 || !strings.Contains(textContent(doc), "$$"+value+"$$") {
			t.Error("oversized math must remain visible source without a rendering attribute")
		}
	}
	boundary := strings.Repeat("x", maxMathSource)
	if len(formulas(rendered(t, New(), "$"+boundary+"$", nil))) != 1 {
		t.Error("formula at the byte limit was rejected")
	}
	unclosed := "$$\n\\frac{a}{b}\n**literal** <img src=x>"
	doc := rendered(t, New(), unclosed, nil)
	if !strings.Contains(textContent(doc), unclosed) || len(elements(doc, "strong"))+len(elements(doc, "img")) != 0 {
		t.Error("unclosed math must be inert visible source")
	}
}

func TestAttachmentAuthorization(t *testing.T) {
	var called []string
	resolver := func(id string) string {
		called = append(called, id)
		if id == "owned_1" {
			return "/s/secret-token/attachments/owned_1?note=one&scope=image"
		}
		return ""
	}
	source := `![owned](attachment:owned_1 "A title") ![other note](attachment:other-2) ` +
		`![external](https://evil.test/track) ![local](/etc/passwd) ![file](file:///etc/passwd) ` +
		`![traversal](attachment:../../secret) ![encoded](attachment:%2e%2e%2fsecret) ![empty](attachment:) ` +
		"![reference][img]\n\n[img]: attachment:owned_1"
	doc := rendered(t, New(), source, resolver)
	if !reflect.DeepEqual(called, []string{"owned_1", "other-2", "owned_1"}) {
		t.Fatalf("resolver saw invalid/external IDs or missed references: %v", called)
	}
	images := elements(doc, "img")
	if len(images) != 2 {
		t.Fatalf("got %d images, want only the 2 authorized images", len(images))
	}
	for _, image := range images {
		if attribute(image, "src") != "/s/secret-token/attachments/owned_1?note=one&scope=image" {
			t.Error("share-scoped attachment URL changed")
		}
	}
	if attribute(images[0], "title") != "A title" || !strings.Contains(textContent(doc), "other note") {
		t.Error("image title/rejected-image fallback lost")
	}
	if len(elements(rendered(t, New(), "![missing](attachment:owned_1)", nil), "img")) != 0 {
		t.Error("nil resolver must not emit an image")
	}
}

func TestAttachmentResolverIsolation(t *testing.T) {
	r := New()
	for i := range 24 {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			t.Parallel()
			url := fmt.Sprintf("/s/token-%d/notes/note-%d/attachments/same-id", i, i)
			doc := rendered(t, r, "![image](attachment:same-id)", func(id string) string {
				if id != "same-id" {
					t.Errorf("wrong ID %q", id)
				}
				return url
			})
			images := elements(doc, "img")
			if len(images) != 1 || attribute(images[0], "src") != url {
				t.Fatal("attachment URL leaked across notes/render calls")
			}
		})
	}
}

func TestRejectUnsafeResolverURLs(t *testing.T) {
	for _, destination := range []string{
		"", "https://evil.test/image", "//evil.test/image", " //evil.test/image", "\t//evil.test/image",
		`/\evil.test/image`, "javascript:alert(1)", "data:image/png;base64,AAAA", "file:///etc/passwd",
		"/attachments/../secret", "/attachments/%2e%2e/secret", "/%2f%2fevil.test/image", "/%5cevil.test/image",
		"/attachments/%0aimage", "/images/image#fragment", "?image=one",
	} {
		t.Run(destination, func(t *testing.T) {
			doc := rendered(t, New(), "![fallback](attachment:one)", func(string) string { return destination })
			if len(elements(doc, "img")) != 0 || !strings.Contains(textContent(doc), "fallback") {
				t.Fatalf("unsafe resolver URL accepted: %q", destination)
			}
		})
	}
	url := `/attachments/one?share=token&quote=" onerror="bad()`
	// Spaces are rejected; quotes alone in otherwise valid local URLs are escaped.
	url = strings.ReplaceAll(url, " ", "%20")
	doc := rendered(t, New(), `![a"&b](attachment:one)`, func(string) string { return url })
	images := elements(doc, "img")
	if len(images) != 1 || attribute(images[0], "src") != url || attribute(images[0], "alt") != `a"&b` {
		t.Error("local URL/alt escaping corrupted an attribute")
	}
}

func TestMaliciousMarkdown(t *testing.T) {
	attacks := []string{
		`<script>alert(document.cookie)</script>`,
		`<img src="https://evil.test/track" onerror="alert(1)">`,
		`<svg/onload=alert(1)>`,
		`<iframe srcdoc="<script>alert(1)</script>"></iframe>`,
		`<button onclick="alert(1)">copy</button>`,
		`[bad](javascript:alert(1))`,
		`[bad](java&#x73;cript:alert(1))`,
		`[bad](jav&#x09;ascript:alert(1))`,
		`[bad](data:text/html;base64,PHNjcmlwdD4=)`,
		`[bad](vbscript:msgbox(1))`,
		`<javascript:alert(1)>`,
		`![bad](data:image/svg+xml;base64,PHN2Zz4=)`,
		`![bad](//evil.test/track)`,
		`![bad](images/../../secret)`,
		"```html\n<script>alert(1)</script><img src=x onerror=alert(1)>\n```",
	}
	for _, source := range attacks {
		t.Run(source, func(t *testing.T) {
			doc := rendered(t, New(), source, func(string) string {
				t.Error("resolver called for malicious/non-attachment image")
				return ""
			})
			if len(elements(doc, "img")) != 0 {
				t.Error("untrusted image survived")
			}
		})
	}
	doc := rendered(t, New(), `2 < 3 & literal "quotes" and <em>raw HTML</em>`, nil)
	if !strings.Contains(textContent(doc), `2 < 3 & literal "quotes" and raw HTML`) || len(elements(doc, "em")) != 0 {
		t.Error("text escaping/raw HTML rejection failed")
	}
}

func TestHighlighting(t *testing.T) {
	doc := rendered(t, New(), "```go\npackage main\nconst s = \"<script>$x$</script>\"\n```", nil)
	codes := elements(doc, "code")
	if len(codes) != 1 || attribute(codes[0], "class") != "language-go" || len(elements(codes[0], "span")) == 0 {
		t.Fatal("Go code was not syntax highlighted")
	}
	if len(formulas(doc)) != 0 || !strings.Contains(textContent(codes[0]), `"<script>$x$</script>"`) {
		t.Error("code source was interpreted or changed")
	}
	for _, info := range []string{"unknown-language", `go\"onmouseover=bad()`} {
		doc := rendered(t, New(), "```"+info+"\n<x>& $not_math$\n```", nil)
		if !strings.Contains(textContent(doc), "<x>& $not_math$") || len(elements(doc, "span")) != 0 {
			t.Error("unknown/unsafe lexer must use escaped plain code")
		}
	}
	large := strings.Repeat("var x = 1\n", maxHighlightSource/10+1)
	doc = rendered(t, New(), "```go\n"+large+"```", nil)
	if len(elements(doc, "span")) != 0 || !strings.Contains(textContent(doc), large) {
		t.Error("large code blocks must fall back to plain source")
	}
}

type failingLexer struct {
	name             string
	panicOnIteration bool
}

func (l *failingLexer) Config() *chroma.Config                         { return &chroma.Config{Name: l.name} }
func (l *failingLexer) SetRegistry(*chroma.LexerRegistry) chroma.Lexer { return l }
func (l *failingLexer) SetAnalyser(func(string) float32) chroma.Lexer  { return l }
func (l *failingLexer) AnalyseText(string) float32                     { return 0 }
func (l *failingLexer) Tokenise(*chroma.TokeniseOptions, string) (chroma.Iterator, error) {
	if !l.panicOnIteration {
		return nil, errors.New("test lexer error")
	}
	return func() chroma.Token { panic(errors.New("test iterator error")) }, nil
}

func TestHighlightLexerErrorsFallBackToSource(t *testing.T) {
	for _, lexer := range []*failingLexer{
		{name: "reader-test-error"},
		{name: "reader-test-panic", panicOnIteration: true},
	} {
		t.Run(lexer.name, func(t *testing.T) {
			lexers.Register(lexer)
			source := "<img src=x onerror=bad()> $not_math$\n"
			doc := rendered(t, New(), "```"+lexer.name+"\n"+source+"```", nil)
			code := elements(doc, "code")
			if len(code) != 1 || textContent(code[0]) != source || len(elements(code[0], "span")) != 0 {
				t.Fatal("lexer failure did not fall back to escaped plain code")
			}
		})
	}
}

func FuzzRenderSafety(f *testing.F) {
	for _, source := range []string{
		"Hello $x_1$", "$$\n\\begin{matrix}a & b \\\\ c & d\\end{matrix}\n$$",
		`$"</span><img src=x onerror=bad()>$`, `![x](attachment:../secret)`,
		`[bad](java&#x73;cript:alert(1))`, "```html\n<img src=x> $x$\n```",
	} {
		f.Add(source)
	}
	r := New()
	f.Fuzz(func(t *testing.T, source string) {
		if len(source) > 64*1024 {
			t.Skip()
		}
		rendered(t, r, source, func(id string) string { return "/notes/current/attachments/" + id + "?share=token" })
	})
}
