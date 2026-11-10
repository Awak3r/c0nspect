package conspectclient

import (
	"context"
	"errors"
	"net/http"
	"net/url"
)

// ListNoteDocuments reads the same permission-filtered endpoint as ListNotes,
// retaining Markdown for local documentation search. List responses have no ETag.
func (c *Client) ListNoteDocuments(ctx context.Context, projectID string) ([]Note, error) {
	if !validID(projectID) {
		return nil, errors.New("project ID must be 32 lowercase hexadecimal characters")
	}
	var result struct {
		Notes []Note `json:"notes"`
	}
	if _, err := c.request(ctx, http.MethodGet, "/projects/"+projectID+"/notes", url.Values{"sort": {"title"}}, nil, "", "", http.StatusOK, &result); err != nil {
		return nil, err
	}
	for i := range result.Notes {
		note := &result.Notes[i]
		if !validID(note.ID) || note.ProjectID != projectID || note.Version < 1 {
			return nil, errors.New("Conspect API returned invalid note metadata")
		}
		if err := validateText(note.Markdown); err != nil {
			return nil, err
		}
		note.ETag = ""
		note.URL = c.origin + "/notes/" + note.ID
	}
	return result.Notes, nil
}
