package render

import (
	"bytes"
	"fmt"
	"html"

	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/parser"
	"github.com/yuin/goldmark/text"
	"github.com/yuin/goldmark/util"
)

// Keep this byte limit in sync with the (additional) browser length check.
const maxMathSource = 16 * 1024

var (
	kindMathInline = ast.NewNodeKind("ReaderMathInline")
	kindMathBlock  = ast.NewNodeKind("ReaderMathBlock")
)

type mathInline struct {
	ast.BaseInline
	value   []byte
	display bool
}

func (n *mathInline) Kind() ast.NodeKind   { return kindMathInline }
func (n *mathInline) Text(_ []byte) []byte { return n.value }
func (n *mathInline) Dump(source []byte, level int) {
	ast.DumpHelper(n, source, level, nil, nil)
}

type mathBlock struct {
	ast.BaseBlock
	value  []byte
	closed bool
}

func (n *mathBlock) Kind() ast.NodeKind { return kindMathBlock }
func (n *mathBlock) IsRaw() bool        { return true }
func (n *mathBlock) Dump(source []byte, level int) {
	ast.DumpHelper(n, source, level, nil, nil)
}

type mathInlineParser struct{}

func (mathInlineParser) Trigger() []byte { return []byte{'$'} }

func (mathInlineParser) Parse(_ ast.Node, reader text.Reader, _ parser.Context) ast.Node {
	line, _ := reader.PeekLine()
	width := 0
	for width < len(line) && line[width] == '$' {
		width++
	}
	if width > 2 {
		reader.Advance(width)
		return ast.NewString(line[:width])
	}
	end := closingDollars(line, width, width)
	if end < 0 || end == width {
		reader.Advance(width)
		return ast.NewString(line[:width])
	}
	reader.Advance(end + width)
	return &mathInline{value: line[width:end], display: width == 2}
}

// closingDollars searches exact delimiter runs, skipping backslash escapes.
// Goldmark itself handles escaped opening dollars and code spans before calling
// our inline parser. Once math starts, its contents must not be parsed as Markdown.
func closingDollars(line []byte, start, width int) int {
	for i := start; i < len(line); {
		switch line[i] {
		case '\\':
			i += 2
		case '$':
			end := i + 1
			for end < len(line) && line[end] == '$' {
				end++
			}
			if end-i == width {
				return i
			}
			i = end
		default:
			i++
		}
	}
	return -1
}

type mathBlockParser struct{}

func (mathBlockParser) Trigger() []byte             { return []byte{'$'} }
func (mathBlockParser) CanInterruptParagraph() bool { return true }
func (mathBlockParser) CanAcceptIndentedLine() bool { return false }

func (mathBlockParser) Open(_ ast.Node, reader text.Reader, pc parser.Context) (ast.Node, parser.State) {
	line, _ := reader.PeekLine()
	pos := pc.BlockOffset()
	if pos < 0 || !bytes.HasPrefix(line[pos:], []byte("$$")) || len(line[pos:]) > 2 && line[pos+2] == '$' {
		return nil, parser.NoChildren
	}
	body := line[pos+2:]
	n := &mathBlock{}
	if end := closingDollars(body, 0, 2); end >= 0 {
		if len(bytes.TrimSpace(body[end+2:])) != 0 {
			return nil, parser.NoChildren
		}
		n.value = append(n.value, body[:end]...)
		n.closed = true
	} else {
		n.value = append(n.value, body...)
	}
	reader.AdvanceToEOL()
	return n, parser.NoChildren
}

func (mathBlockParser) Continue(node ast.Node, reader text.Reader, _ parser.Context) parser.State {
	n := node.(*mathBlock)
	if n.closed {
		return parser.Close
	}
	line, _ := reader.PeekLine()
	if end := closingDollars(line, 0, 2); end >= 0 && len(bytes.TrimSpace(line[end+2:])) == 0 {
		n.value = append(n.value, line[:end]...)
		n.closed = true
		reader.AdvanceToEOL()
		return parser.Close
	}
	n.value = append(n.value, line...)
	reader.AdvanceToEOL()
	return parser.Continue | parser.NoChildren
}

func (mathBlockParser) Close(ast.Node, text.Reader, parser.Context) {}

func (r *nodeRenderer) renderInlineMath(w util.BufWriter, _ []byte, node ast.Node, entering bool) (ast.WalkStatus, error) {
	if entering {
		n := node.(*mathInline)
		writeMath(w, n.value, n.display, false, true)
	}
	return ast.WalkSkipChildren, nil
}

func (r *nodeRenderer) renderBlockMath(w util.BufWriter, _ []byte, node ast.Node, entering bool) (ast.WalkStatus, error) {
	if entering {
		n := node.(*mathBlock)
		writeMath(w, n.value, true, true, n.closed)
	}
	return ast.WalkSkipChildren, nil
}

func writeMath(w util.BufWriter, value []byte, display, block, closed bool) {
	delimiter, mode, class := "$", "inline", "math-inline"
	if display {
		delimiter, mode, class = "$$", "block", "math-display"
	}
	escaped := html.EscapeString(string(value))
	fallback := delimiter + escaped
	if closed {
		fallback += delimiter
	}
	if !closed || len(value) > maxMathSource {
		if block {
			_, _ = fmt.Fprintf(w, "<pre class=\"math-source\">%s</pre>\n", fallback)
		} else {
			_, _ = w.WriteString(fallback)
		}
		return
	}
	tag := "span"
	if block {
		tag = "div"
	}
	_, _ = fmt.Fprintf(w, `<%s class="math %s" data-math="%s" data-tex="%s">%s</%s>`, tag, class, mode, escaped, fallback, tag)
	if block {
		_ = w.WriteByte('\n')
	}
}
