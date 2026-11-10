// Package documents extracts reference passages without rewriting source Markdown.
package documents

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/text"
)

type Section struct {
	ID        string `json:"id"`
	Heading   string `json:"heading"`
	Level     int    `json:"level"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
	Start     int    `json:"-"`
	End       int    `json:"-"`
}

type Document struct {
	Source   string
	Sections []Section
	lines    []int
}

func Parse(source string) Document {
	d := Document{Source: source, lines: []int{0}, Sections: []Section{}}
	for i, ch := range source {
		if ch == '\n' && i+1 < len(source) {
			d.lines = append(d.lines, i+1)
		}
	}
	data := []byte(source)
	root := goldmark.New().Parser().Parse(text.NewReader(data))
	_ = ast.Walk(root, func(node ast.Node, entering bool) (ast.WalkStatus, error) {
		h, ok := node.(*ast.Heading)
		if !entering || !ok || h.Lines().Len() == 0 {
			return ast.WalkContinue, nil
		}
		line := d.line(h.Lines().At(0).Start)
		d.Sections = append(d.Sections, Section{ID: fmt.Sprintf("s%d", len(d.Sections)+1), Heading: string(h.Text(data)), Level: h.Level, StartLine: line, Start: d.lines[line-1]})
		return ast.WalkContinue, nil
	})
	for i := range d.Sections {
		s := &d.Sections[i]
		s.End = len(source)
		for j := i + 1; j < len(d.Sections); j++ {
			if d.Sections[j].Level <= s.Level {
				s.End = d.Sections[j].Start
				break
			}
		}
		s.EndLine = d.line(max(s.Start, s.End-1))
	}
	introEnd := len(source)
	if len(d.Sections) > 0 {
		introEnd = d.Sections[0].Start
	}
	if introEnd > 0 || len(d.Sections) == 0 {
		intro := Section{ID: "s0", Heading: "Введение", StartLine: 1, EndLine: d.line(max(0, introEnd-1)), End: introEnd}
		d.Sections = append([]Section{intro}, d.Sections...)
	}
	return d
}

func (d Document) line(offset int) int {
	return max(1, sort.Search(len(d.lines), func(i int) bool { return d.lines[i] > offset }))
}

func (d Document) Select(id string) (Section, error) {
	if id == "" {
		return Section{StartLine: 1, EndLine: d.line(max(0, len(d.Source)-1)), End: len(d.Source)}, nil
	}
	for _, s := range d.Sections {
		if s.ID == id {
			return s, nil
		}
	}
	return Section{}, errors.New("раздел не найден; получите актуальное оглавление")
}

type Passage struct {
	Markdown   string `json:"markdown"`
	StartLine  int    `json:"start_line"`
	EndLine    int    `json:"end_line"`
	Offset     int    `json:"offset"`
	NextOffset int    `json:"next_offset"`
	HasMore    bool   `json:"has_more"`
}

// Offsets count Unicode code points relative to the selected section, not bytes.
func (d Document) Read(s Section, offset, size int) (Passage, error) {
	if offset < 0 || size < 1 {
		return Passage{}, errors.New("offset должен быть >= 0, max_chars > 0")
	}
	runes := []rune(d.Source[s.Start:s.End])
	if offset > len(runes) {
		return Passage{}, errors.New("offset выходит за пределы выбранного текста")
	}
	end := min(len(runes), offset+size)
	startByte := s.Start + len(string(runes[:offset]))
	body := string(runes[offset:end])
	return Passage{Markdown: body, StartLine: d.line(startByte), EndLine: d.line(max(startByte, startByte+len(body)-1)), Offset: offset, NextOffset: end, HasMore: end < len(runes)}, nil
}

func Terms(query string) ([]string, error) {
	if !utf8.ValidString(query) || len(query) > 1000 || strings.ContainsRune(query, 0) {
		return nil, errors.New("query должен быть UTF-8 без NUL, до 1000 байт")
	}
	words := strings.FieldsFunc(strings.ToLower(query), func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsNumber(r) && r != '_' })
	terms := []string{}
	seen := map[string]bool{}
	for _, word := range words {
		if !seen[word] {
			terms = append(terms, word)
			seen[word] = true
		}
	}
	if len(terms) == 0 || len(terms) > 20 {
		return nil, errors.New("query должен содержать от 1 до 20 различных слов")
	}
	return terms, nil
}

type Match struct {
	Section Section
	Passage Passage
	Score   int
	Terms   []string
}

// BestMatch returns one passage per note. Matching is lexical (substring), not semantic.
func (d Document) BestMatch(title string, terms []string) Match {
	best := Match{}
	for i, section := range d.Sections {
		// Score disjoint heading blocks so a parent does not swallow child matches.
		block := section
		if i+1 < len(d.Sections) {
			block.End = d.Sections[i+1].Start
		}
		body := d.Source[block.Start:block.End]
		lower := strings.ToLower(body)
		score, first := 0, -1
		matched := []string{}
		for _, term := range terms {
			found := false
			if strings.Contains(strings.ToLower(title), term) {
				score += 8
				found = true
			}
			if strings.Contains(strings.ToLower(section.Heading), term) {
				score += 5
				found = true
			}
			if pos := strings.Index(lower, term); pos >= 0 {
				score += 2
				found = true
				if first < 0 || pos < first {
					first = pos
				}
			}
			if found {
				matched = append(matched, term)
			}
		}
		if score <= best.Score {
			continue
		}
		offset := 0
		if first > 0 {
			// Lowercasing can change byte lengths; rune positions remain aligned.
			offset = max(0, utf8.RuneCountInString(lower[:first])-160)
		}
		passage, _ := d.Read(block, offset, 900)
		best = Match{Section: section, Passage: passage, Score: score, Terms: matched}
	}
	return best
}
