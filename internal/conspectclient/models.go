package conspectclient

// Config is trusted startup configuration, never supplied by MCP tool arguments.
type Config struct {
	BaseURL    string
	APIKey     string
	APIKeyFile string
	FilesRoot  string
}

type Project struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

type NoteSummary struct {
	ID        string `json:"id"`
	ProjectID string `json:"project_id"`
	Title     string `json:"title"`
	Version   int64  `json:"version"`
	Shared    bool   `json:"shared"`
	UpdatedAt string `json:"updated_at"`
}

type Note struct {
	ID          string       `json:"id"`
	ProjectID   string       `json:"project_id"`
	Title       string       `json:"title"`
	Markdown    string       `json:"markdown"`
	Version     int64        `json:"version"`
	Shared      bool         `json:"shared"`
	ETag        string       `json:"etag"`
	URL         string       `json:"url"`
	Attachments []Attachment `json:"attachments,omitempty"`
}

type Attachment struct {
	ID     string `json:"id"`
	NoteID string `json:"note_id"`
	Name   string `json:"name"`
	MIME   string `json:"mime_type"`
	Size   int64  `json:"size"`
}

type UploadedImage struct {
	Attachment Attachment `json:"attachment"`
	Markdown   string     `json:"markdown"`
}
