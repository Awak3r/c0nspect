package render

import (
	"bytes"
	"fmt"
	"html"

	"github.com/alecthomas/chroma/v2"
	chromahtml "github.com/alecthomas/chroma/v2/formatters/html"
	"github.com/alecthomas/chroma/v2/lexers"
	"github.com/alecthomas/chroma/v2/styles"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/util"
)

const (
	maxHighlightSource         = 128 * 1024
	maxHighlightDocumentSource = 128 * 1024
)

var codeStyle = styles.Get("github")

func codeFormatter() *chromahtml.Formatter {
	return chromahtml.New(chromahtml.WithClasses(true), chromahtml.ClassPrefix("syntax-"),
		chromahtml.PreventSurroundingPre(true))
}

func (r *nodeRenderer) renderCodeBlock(w util.BufWriter, source []byte, node ast.Node, entering bool) (ast.WalkStatus, error) {
	if !entering {
		return ast.WalkContinue, nil
	}
	n := node.(*ast.FencedCodeBlock)
	code := n.Lines().Value(source)
	language := string(n.Language(source))
	validLanguage := safeLanguage(language)
	_, _ = w.WriteString(`<pre class="syntax-chroma"><code`)
	if validLanguage {
		_, _ = fmt.Fprintf(w, ` class="language-%s"`, language)
	}
	_ = w.WriteByte('>')

	var highlighted string
	var ok bool
	if validLanguage && len(code) <= maxHighlightSource && len(code) <= r.highlightBudget {
		// Bound total expanded output/work even when a document has many blocks.
		// Apply the same budget on hits so cache history cannot change rendering.
		r.highlightBudget -= len(code)
		highlighted, ok = r.highlights.getOrCompute(language, string(code), func() (string, bool) {
			var output bytes.Buffer
			if !highlight(&output, language, string(code)) {
				return "", false
			}
			return output.String(), true
		})
	}
	if ok {
		_, _ = w.WriteString(highlighted)
	} else {
		_, _ = w.WriteString(html.EscapeString(string(code)))
	}
	_, _ = w.WriteString("</code></pre>\n")
	return ast.WalkSkipChildren, nil
}

func safeLanguage(language string) bool {
	if len(language) == 0 || len(language) > 64 {
		return false
	}
	for _, c := range []byte(language) {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '+' || c == '-') {
			return false
		}
	}
	return true
}

func highlight(output *bytes.Buffer, language, code string) bool {
	lexer := lexers.Get(language)
	if lexer == nil {
		return false
	}
	iterator, err := chroma.Coalesce(lexer).Tokenise(nil, code)
	if err != nil {
		return false
	}
	return chroma.RecoveringFormatter(codeFormatter()).Format(output, codeStyle, iterator) == nil
}
