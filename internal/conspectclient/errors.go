package conspectclient

import (
	"fmt"
	"net/http"
)

// APIError reports only a status and a locally curated message. Response bodies,
// request URLs, authentication headers and server request IDs are never exposed.
// No error triggers an automatic retry.
type APIError struct {
	StatusCode int
}

func (e *APIError) Error() string {
	var message string
	switch e.StatusCode {
	case http.StatusBadRequest:
		message = "invalid request; check the supplied arguments"
	case http.StatusUnauthorized:
		message = "authentication failed; check the configured API key"
	case http.StatusForbidden:
		message = "access denied; check the API key's scopes and resource grants"
	case http.StatusNotFound:
		message = "resource not found or not accessible to this API key"
	case http.StatusRequestTimeout:
		message = "server timed out handling the request"
	case http.StatusConflict:
		message = "request conflicts with the current resource state"
	case http.StatusPreconditionFailed:
		message = "note changed; refetch it, recompute the edit against the latest Markdown, and explicitly update using its new ETag"
	case http.StatusRequestEntityTooLarge:
		message = "request exceeds the server's size or storage limits"
	case http.StatusUnsupportedMediaType:
		message = "unsupported content or image format"
	case http.StatusUnprocessableEntity:
		message = "invalid note or image; check title, UTF-8 content, size and image dimensions"
	case http.StatusPreconditionRequired:
		message = "update requires the exact strong ETag from the latest note response"
	case http.StatusTooManyRequests:
		message = "rate limited; wait before explicitly trying again; no automatic retry was performed"
	default:
		switch {
		case e.StatusCode >= 300 && e.StatusCode < 400:
			message = "redirect refused; configure the canonical API origin"
		case e.StatusCode >= 500:
			message = "server error; no automatic retry was performed"
		default:
			message = "unexpected response status"
		}
	}
	return fmt.Sprintf("Conspect API HTTP %d: %s", e.StatusCode, message)
}

func uncertainWrite(method string, err error) error {
	if err == nil || method == http.MethodGet {
		return err
	}
	return fmt.Errorf("%w; write outcome may be unknown: inspect current state before explicitly retrying", err)
}
