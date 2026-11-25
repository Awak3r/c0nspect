package web

import (
	"context"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"conspect/internal/store"

	"golang.org/x/net/html"
)

func libraryTestApp(t *testing.T) *App {
	t.Helper()
	app, err := New(nil, Config{BaseURL: "http://localhost", Secret: make([]byte, 32), DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	return app
}

func libraryTestPage(t *testing.T, app *App, name string, data pageData, owner bool) *html.Node {
	t.Helper()
	r := httptest.NewRequest("GET", "/", nil)
	if owner {
		r = r.WithContext(context.WithValue(r.Context(), sessionKey{}, store.Session{CSRFToken: "test-csrf"}))
	}
	w := httptest.NewRecorder()
	app.page(w, r, 200, name, data)
	browserTestStatus(t, w, 200)
	return browserTestDocument(t, w)
}

func TestLibraryPrimaryActions(t *testing.T) {
	app := libraryTestApp(t)
	changed := time.Date(2026, 11, 12, 15, 0, 0, 0, time.UTC)
	project := store.Project{ID: "project", Name: "Математика", UpdatedAt: changed}
	note := store.Note{ID: "note", ProjectID: project.ID, Title: "Ряды", UpdatedAt: changed}
	data := pageData{Project: project, Projects: []store.Project{project}}

	projects := libraryTestPage(t, app, "projects", pageData{Projects: data.Projects}, true)
	creation := browserTestForm(t, projects, "/projects")
	if creation.Parent.Data != "details" || hasLibraryAttr(creation.Parent, "open") {
		t.Fatal("creation must be a collapsed disclosure by default")
	}
	if !browserTestHasLink(projects, "/projects/project") {
		t.Error("library lost the project link")
	}
	times := browserTestElements(projects, "time")
	if len(times) != 1 || browserTestText(times[0]) != "12.11.2026" || browserTestAttr(times[0], "datetime") != "2026-11-12T15:00:00Z" {
		t.Error("project row did not show the short date with machine-readable time")
	}

	for _, empty := range []bool{true, false} {
		if !empty {
			data.Notes = []store.Note{note}
		}
		doc := libraryTestPage(t, app, "project", data, true)
		form := browserTestForm(t, doc, "/projects/project/notes")
		if form.Parent.Data != "details" || hasLibraryAttr(form.Parent, "open") != empty {
			t.Errorf("import disclosure should start open only for an empty project (empty=%v)", empty)
		}
		if browserTestAttr(form, "method") != "post" || browserTestAttr(form, "enctype") != "multipart/form-data" || browserTestInput(t, form, "csrf") != "test-csrf" {
			t.Error("moving import lost the native upload form or CSRF")
		}
		if browserTestHasLink(doc, "/projects/project/manage") || browserTestHasLink(doc, "/notes/note") == empty {
			t.Error("project page should link directly to reading without a management detour")
		}
		remove := browserTestForm(t, doc, "/projects/project/delete")
		if remove.Parent.Data != "details" || hasLibraryAttr(remove.Parent, "open") || browserTestInput(t, remove, "csrf") != "test-csrf" || browserTestInput(t, remove, "confirm") != "DELETE" {
			t.Fatal("project deletion must be collapsed and require confirmation")
		}
		summaries := browserTestElements(remove.Parent, "summary")
		if len(summaries) != 1 || browserTestAttr(summaries[0], "aria-label") != "Удалить проект" || len(browserTestElements(summaries[0], "svg")) != 1 {
			t.Error("project delete must use an accessible inline SVG icon")
		}
	}
}

func TestLibraryRowsOfferSharingAndConfirmedDeletion(t *testing.T) {
	app := libraryTestApp(t)
	project := store.Project{ID: "project", Name: "Математика"}
	notes := []store.Note{
		{ID: "private", ProjectID: project.ID, Title: "Ряды", Version: 1},
		{ID: "shared", ProjectID: project.ID, Title: "Графы", Version: 5, Shared: true},
	}
	for _, name := range []string{"project", "projects"} {
		t.Run(name, func(t *testing.T) {
			data := pageData{Notes: notes}
			if name == "project" {
				data.Project = project
			} else {
				data.Query = "математика"
			}
			doc := libraryTestPage(t, app, name, data, true)
			rows := browserTestElements(doc, "li")
			if len(rows) != len(notes) {
				t.Fatalf("got %d note rows, want %d", len(rows), len(notes))
			}
			for i, note := range notes {
				row := rows[i]
				path := "/notes/" + note.ID
				if !browserTestHasLink(row, path) || browserTestHasLink(row, path+"/manage") {
					t.Errorf("note %s should link to the reader, not the old settings", note.ID)
				}
				browserTestForm(t, row, path+"/share")
				remove := browserTestForm(t, row, path+"/delete")
				if remove.Parent.Data != "details" || hasLibraryAttr(remove.Parent, "open") || browserTestInput(t, remove, "csrf") != "test-csrf" || browserTestInput(t, remove, "confirm") != "DELETE" || browserTestInput(t, remove, "version") != strconv.FormatInt(note.Version, 10) {
					t.Fatal("note deletion must be collapsed, confirmed and versioned")
				}
				summaries := browserTestElements(remove.Parent, "summary")
				if len(summaries) != 1 || browserTestAttr(summaries[0], "aria-label") != "Удалить конспект: "+note.Title || len(browserTestElements(summaries[0], "svg")) != 1 {
					t.Error("note delete must use an accessible inline SVG icon")
				}
				if len(browserTestElements(row, "form")) != 2 {
					t.Error("note row exposes controls other than sharing and deleting")
				}
				if browserTestHasLink(row, path+"/share") || strings.Contains(browserTestText(row), "По ссылке") {
					t.Errorf("note %s contains a persistent share badge or management link", note.ID)
				}
			}
		})
	}
}

func hasLibraryAttr(node *html.Node, name string) bool {
	for _, attr := range node.Attr {
		if attr.Key == name {
			return true
		}
	}
	return false
}

func TestReaderKeepsLeadingDocumentTitleWithoutDuplication(t *testing.T) {
	app := libraryTestApp(t)
	for _, tc := range []struct {
		name, source string
		headings     int
		match        bool
	}{
		{"matching formatted title", "# Графы & **деревья**\n\nТекст", 1, true},
		{"matching setext title", "Графы & деревья\n================\n\nТекст", 1, true},
		{"different title", "# Другой раздел\n\nТекст", 2, false},
		{"same heading later", "Вступление\n\n# Графы & деревья\n\nТекст", 2, false},
		{"no heading", "Текст", 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			project := store.Project{ID: "project", Name: "Дискретная математика"}
			note := store.Note{ID: "note", ProjectID: project.ID, Title: "Графы & деревья"}
			content, err := app.renderer.Render(tc.source, nil)
			if err != nil {
				t.Fatal(err)
			}
			match := documentHasTitle(content, note.Title)
			if match != tc.match {
				t.Fatalf("leading title match = %v, want %v", match, tc.match)
			}
			data := pageData{Note: note, Project: project, Content: content, DocumentHasTitle: match}
			for _, owner := range []bool{true, false} {
				doc := libraryTestPage(t, app, "reader", data, owner)
				if headings := browserTestElements(doc, "h1"); len(headings) != tc.headings || browserTestText(headings[0]) != note.Title {
					t.Errorf("reader headings did not preserve source and title (owner=%v)", owner)
				}
				if browserTestHasLink(doc, "/projects/project") != owner || len(browserTestElements(doc, "form")) != 0 || len(browserTestElements(doc, "button")) != 0 {
					t.Errorf("reader leaked controls or lost its back link (owner=%v)", owner)
				}
				if tc.name == "matching formatted title" && len(browserTestElements(doc, "strong")) != 1 {
					t.Error("reader lost title formatting")
				}
			}
		})
	}
}
