package mcpserver

import (
	"context"
	"slices"

	"conspect/internal/conspectclient"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type remotePrepareInput struct {
	SourceText      string `json:"source_text" jsonschema:"Полный прочитанный текст источника; URL не заменяет содержимое"`
	Title           string `json:"title,omitempty"`
	SourceReference string `json:"source_reference,omitempty"`
	Language        string `json:"language,omitempty"`
	Focus           string `json:"focus,omitempty"`
	Preferences     string `json:"preferences,omitempty"`
}

// NewRemote shares the stdio tools but never exposes the VPS filesystem. A new
// instance is bound to the current authenticated request, not a shared session.
func NewRemote(client *conspectclient.Client, scopes []string) *mcp.Server {
	s := New(client)
	s.RemoveTools("conspect_upload_markdown", "conspect_upload_image", "conspect_prepare_note")
	if !slices.Contains(scopes, "notes:read") {
		s.RemoveTools("conspect_list_projects", "conspect_list_notes", "conspect_get_note", "conspect_search_docs", "conspect_docs_outline", "conspect_read_docs")
	}
	if !slices.Contains(scopes, "notes:write") {
		s.RemoveTools("conspect_create_note", "conspect_update_note")
	}
	mcp.AddTool(s, tool("conspect_prepare_note", "Вернуть модели руководство по созданию ADHD-конспекта из полного source_text. Формулы — LaTeX для KaTeX. Не вызывает LLM и не сохраняет результат. Локальные файлы VPS недоступны.", true, false),
		func(_ context.Context, _ *mcp.CallToolRequest, in remotePrepareInput) (*mcp.CallToolResult, prepareOutput, error) {
			prompt, err := prepare(client, prepareInput{SourceText: in.SourceText, Title: in.Title, SourceReference: in.SourceReference, Language: in.Language, Focus: in.Focus, Preferences: in.Preferences})
			return nil, prepareOutput{Prompt: prompt}, err
		})
	return s
}
