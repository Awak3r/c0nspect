package web

import (
	"strings"

	"conspect/internal/store"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/text"
)

// Diagnostics belong to management, never to the shared reader or its API data.
func imageWarnings(source string, files []store.Attachment) []string {
	available := make(map[string]bool, len(files))
	for _, file := range files {
		available[file.ID] = file.MIME == "image/png" || file.MIME == "image/jpeg" || file.MIME == "image/webp"
	}
	seen := make(map[string]bool)
	var warnings []string
	node := goldmark.New().Parser().Parse(text.NewReader([]byte(source)))
	_ = ast.Walk(node, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		img, ok := n.(*ast.Image)
		if !entering || !ok {
			return ast.WalkContinue, nil
		}
		reference := string(img.Destination)
		if strings.HasPrefix(reference, "attachment:") && available[strings.TrimPrefix(reference, "attachment:")] {
			return ast.WalkContinue, nil
		}
		if seen[reference] {
			return ast.WalkContinue, nil
		}
		seen[reference] = true
		runes := []rune(reference)
		if len(runes) > 200 {
			reference = string(runes[:200]) + "…"
		}
		message := "Изображение не связано с конспектом: " + reference
		if strings.HasPrefix(reference, "http://") || strings.HasPrefix(reference, "https://") {
			message = "Внешнее изображение отключено; загрузите файл в сервис: " + reference
		}
		warnings = append(warnings, message)
		if len(warnings) >= 16 {
			return ast.WalkStop, nil
		}
		return ast.WalkContinue, nil
	})
	return warnings
}
