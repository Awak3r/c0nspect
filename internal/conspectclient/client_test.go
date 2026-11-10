package conspectclient

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

const (
	testProjectID = "11111111111111111111111111111111"
	testNoteID    = "22222222222222222222222222222222"
	testKey       = "csp_test-secret-not-for-output"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func testClient(t *testing.T, trip roundTripFunc) *Client {
	t.Helper()
	client, err := New(Config{BaseURL: "https://example.invalid/api/v1/", APIKey: testKey})
	if err != nil {
		t.Fatal(err)
	}
	client.http.Transport = trip
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func jsonResponse(status int, body, etag string) *http.Response {
	headers := http.Header{"Content-Type": {"application/json"}}
	if etag != "" {
		headers.Set("ETag", etag)
	}
	return &http.Response{StatusCode: status, Header: headers, Body: io.NopCloser(strings.NewReader(body))}
}

func TestNoteRequestsUseExactContract(t *testing.T) {
	calls := 0
	client := testClient(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Header.Get("Authorization") != "Bearer "+testKey || r.URL.RawQuery != "" || r.GetBody != nil {
			t.Fatal("incorrect authentication, query or write replay hook")
		}
		if r.URL.Host != "example.invalid" || r.URL.Path != "/api/v1/notes/"+testNoteID {
			t.Fatal("incorrect note endpoint")
		}
		if r.Method == http.MethodPut {
			if r.Header.Get("If-Match") != `"v7"` {
				t.Fatal("If-Match was not preserved")
			}
			var input map[string]string
			if err := json.NewDecoder(r.Body).Decode(&input); err != nil || len(input) != 2 || input["title"] != "Title" || input["markdown"] != "# Source" {
				t.Fatal("incorrect update body")
			}
		} else if r.Method != http.MethodGet {
			t.Fatal("unexpected method")
		}
		return jsonResponse(200, `{"id":"`+testNoteID+`","project_id":"`+testProjectID+`","version":8,"title":"Title","markdown":"# Source","shared":true,"etag":"untrusted","url":"https://untrusted.invalid/public"}`, `"v8"`), nil
	})
	for _, get := range []bool{true, false} {
		var note Note
		var err error
		if get {
			note, err = client.GetNote(context.Background(), testNoteID)
		} else {
			note, err = client.UpdateNote(context.Background(), testNoteID, "Title", "# Source", `"v7"`)
		}
		if err != nil {
			t.Fatal(err)
		}
		if note.ETag != `"v8"` || note.URL != "https://example.invalid/notes/"+testNoteID || note.Attachments == nil {
			t.Fatal("incorrect note normalization")
		}
	}
	if calls != 2 {
		t.Fatal("unexpected extra request")
	}
}

func TestSummaryQueryAndEmptyLists(t *testing.T) {
	client := testClient(t, func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/api/v1/projects" {
			return jsonResponse(200, `{"projects":null}`, ""), nil
		}
		if r.URL.Path != "/api/v1/projects/"+testProjectID+"/notes" || r.URL.Query().Get("q") != "x & ?/#" || r.URL.Query().Get("sort") != "title" {
			t.Fatal("incorrect query encoding")
		}
		return jsonResponse(200, `{"notes":[{"id":"`+testNoteID+`","project_id":"`+testProjectID+`","version":1,"markdown":"must not be exposed"}]}`, ""), nil
	})
	projects, err := client.ListProjects(context.Background())
	if err != nil || projects == nil || len(projects) != 0 {
		t.Fatal("empty projects must be a non-nil slice")
	}
	notes, err := client.ListNotes(context.Background(), testProjectID, "x & ?/#", "title")
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(notes)
	if err != nil || strings.Contains(string(encoded), "markdown") || strings.Contains(string(encoded), "must not be exposed") {
		t.Fatal("summary leaked Markdown")
	}
}

func TestRejectedInputsNeverReachTransport(t *testing.T) {
	client := testClient(t, func(*http.Request) (*http.Response, error) {
		t.Fatal("invalid input reached transport")
		return nil, nil
	})
	for _, etag := range []string{"", "*", `W/"v1"`, `"v01"`, `"v0"`, `"v+1"`, `"v1", "v2"`, `"v9223372036854775808"`} {
		if _, err := client.UpdateNote(context.Background(), testNoteID, "Title", "", etag); err == nil {
			t.Fatal("invalid ETag accepted")
		}
	}
	for _, id := range []string{"../notes", strings.Repeat("a", 31), strings.Repeat("A", 32), testNoteID + "?token=hidden"} {
		if _, err := client.GetNote(context.Background(), id); err == nil {
			t.Fatal("invalid ID accepted")
		}
	}
	for _, title := range []string{" ", strings.Repeat("я", 301), "nul\x00", string([]byte{0xff})} {
		if _, err := client.CreateNote(context.Background(), testProjectID, title, ""); err == nil {
			t.Fatal("invalid title accepted")
		}
	}
	for _, markdown := range []string{"nul\x00", string([]byte{0xff}), strings.Repeat("x", maxMarkdownBytes+1)} {
		if _, err := client.CreateNote(context.Background(), testProjectID, "Title", markdown); err == nil {
			t.Fatal("invalid Markdown accepted")
		}
	}
}

func TestErrorsAreCuratedAndWritesNotRetried(t *testing.T) {
	for _, status := range []int{302, 401, 412, 429, 500} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			calls := 0
			client := testClient(t, func(*http.Request) (*http.Response, error) {
				calls++
				response := jsonResponse(status, testKey+" https://hidden.invalid/?token=secret", "")
				response.Header.Set("Location", "https://hidden.invalid/?token=secret")
				return response, nil
			})
			_, err := client.UpdateNote(context.Background(), testNoteID, "Title", "", `"v1"`)
			var apiErr *APIError
			if !errors.As(err, &apiErr) || apiErr.StatusCode != status || calls != 1 {
				t.Fatal("status was lost or request retried")
			}
			if strings.Contains(err.Error(), testKey) || strings.Contains(err.Error(), "hidden.invalid") || strings.Contains(err.Error(), "token=secret") {
				t.Fatal("error leaked untrusted content")
			}
			if status == 412 && !strings.Contains(err.Error(), "recompute") {
				t.Fatal("conflict error must explain safe recovery")
			}
		})
	}
	calls := 0
	client := testClient(t, func(*http.Request) (*http.Response, error) {
		calls++
		return nil, errors.New(testKey + " https://hidden.invalid/?token=secret")
	})
	_, err := client.CreateNote(context.Background(), testProjectID, "Title", "")
	if err == nil || !strings.Contains(err.Error(), "outcome may be unknown") || strings.Contains(err.Error(), testKey) || strings.Contains(err.Error(), "hidden.invalid") || calls != 1 {
		t.Fatal("uncertain POST must be sanitized and must not retry")
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := client.ListProjects(context.Background()); err == nil || calls != 1 {
		t.Fatal("closed client performed a request")
	}
}
