package web

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"conspect/internal/store"
)

// This template check needs no database or browser process.
func TestCompactManagementTemplates(t *testing.T) {
	app, err := New(nil, Config{BaseURL: "http://localhost", Secret: make([]byte, 32), DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	project := store.Project{ID: strings.Repeat("a", 32), Name: "Математика"}
	note := store.Note{ID: strings.Repeat("b", 32), ProjectID: project.ID, Title: "Первый конспект", Version: 2, Shared: true}
	other := store.Note{ID: strings.Repeat("c", 32), ProjectID: project.ID, Title: "Второй конспект", Version: 1}
	render := func(name string, data pageData) *httptest.ResponseRecorder {
		t.Helper()
		response := httptest.NewRecorder()
		app.page(response, httptest.NewRequest("GET", "/", nil), 200, name, data)
		browserTestStatus(t, response, 200)
		return response
	}

	page := render("manage", pageData{Project: project, Notes: []store.Note{note, other}})
	doc := browserTestDocument(t, page)
	for _, n := range []store.Note{note, other} {
		if !browserTestHasLink(doc, "/notes/"+n.ID) || !browserTestHasLink(doc, "/notes/"+n.ID+"/manage") {
			t.Error("compact list omitted reading or settings link")
		}
	}
	for _, form := range browserTestElements(doc, "form") {
		if strings.HasPrefix(browserTestAttr(form, "action"), "/notes/") {
			t.Error("project management still contains individual note forms")
		}
	}
	if len(browserTestElements(doc, "article")) != 0 {
		t.Error("project management still repeats note settings cards")
	}
	for _, details := range browserTestElements(doc, "details") {
		for _, attr := range details.Attr {
			if attr.Key == "open" {
				t.Error("nonempty project settings should be collapsed")
			}
		}
	}

	page = render("manage-note", pageData{Project: project, Projects: []store.Project{project}, Note: note, Entries: []noteEntry{{Note: note}}})
	doc = browserTestDocument(t, page)
	for _, action := range []string{"metadata", "replace", "attachments", "delete"} {
		browserTestForm(t, doc, "/notes/"+note.ID+"/"+action)
	}
	if !browserTestHasLink(doc, "/projects/"+project.ID+"/manage") || !browserTestHasLink(doc, "/notes/"+note.ID+"/share") {
		t.Error("note settings omitted return or sharing link")
	}
	if strings.Contains(page.Body.String(), other.Title) {
		t.Error("settings page contains another note")
	}
	if browserTestInput(t, browserTestForm(t, doc, "/notes/"+note.ID+"/replace"), "version") != "2" {
		t.Error("note settings lost optimistic concurrency version")
	}

	page = render("manage", pageData{Project: project})
	if !strings.Contains(page.Body.String(), "disclosure\" open>") {
		t.Error("empty project should expose the import form")
	}
	response := httptest.NewRecorder()
	app.Handler().ServeHTTP(response, httptest.NewRequest("GET", "/notes/"+note.ID+"/manage", nil))
	browserTestRedirect(t, response, "/login")
}

func TestMinimalInterfaceCopy(t *testing.T) {
	app, err := New(nil, Config{BaseURL: "http://localhost", Secret: make([]byte, 32), DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	project := store.Project{ID: "project", Name: "Мой проект", Description: "Моё описание проекта"}
	note := store.Note{ID: "note", ProjectID: project.ID, Title: "Мой конспект", Version: 1}
	data := pageData{Project: project, Projects: []store.Project{project}, Note: note, Notes: []store.Note{note}, Entries: []noteEntry{{Note: note}}}
	for _, name := range []string{"login", "projects", "project", "manage", "manage-note", "share", "keys"} {
		t.Run(name, func(t *testing.T) {
			page := httptest.NewRecorder()
			app.page(page, httptest.NewRequest("GET", "/", nil), 200, name, data)
			browserTestStatus(t, page, 200)
			for _, phrase := range []string{"Ваши темы, конспекты и идеи", "Собирайте конспекты по темам", "Ваши проекты и материалы", "Отдельное место для предмета", "Без описания", "Раскройте ключ"} {
				if strings.Contains(page.Body.String(), phrase) {
					t.Errorf("unnecessary interface copy remains: %s", phrase)
				}
			}
			if (name == "projects" || name == "project") && !strings.Contains(page.Body.String(), project.Description) {
				t.Error("user-written project description was removed")
			}
			if name == "login" && (len(browserTestElements(browserTestDocument(t, page), "h1")) != 1 || strings.Contains(page.Body.String(), "auth-intro")) {
				t.Error("login should contain only its form, not an introductory column")
			}
		})
	}
}

func TestCompactAPIKeyTemplates(t *testing.T) {
	app, err := New(nil, Config{BaseURL: "http://localhost", Secret: make([]byte, 32), DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	past, future := time.Now().Add(-time.Hour), time.Now().Add(time.Hour)
	keys := []store.APIKey{
		{ID: "active", Name: "Рабочий MCP", ExpiresAt: &future, Scopes: []string{"notes:read"}, TokenHash: "private-hash-not-for-ui"},
		{ID: "expired", Name: "Старый клиент", ExpiresAt: &past},
		{ID: "revoked", Name: "Отозванный клиент", RevokedAt: &past},
	}
	render := func(data pageData) *httptest.ResponseRecorder {
		t.Helper()
		response := httptest.NewRecorder()
		app.page(response, httptest.NewRequest("GET", "/settings/api-keys", nil), 200, "keys", data)
		browserTestStatus(t, response, 200)
		return response
	}
	page := render(pageData{Keys: visibleAPIKeys(keys, true), ShowRevoked: true})
	doc := browserTestDocument(t, page)
	cards := 0
	for _, details := range browserTestElements(doc, "details") {
		for _, attr := range details.Attr {
			if attr.Key == "open" {
				t.Error("existing keys and creation form should be collapsed")
			}
		}
		if browserTestAttr(details, "name") != "api-key" {
			continue
		}
		summary := browserTestElements(details, "summary")[0]
		want := []string{"Действует", "Истёк", "Отозван"}[cards]
		if !strings.Contains(browserTestText(summary), keys[cards].Name) || !strings.Contains(browserTestText(summary), want) {
			t.Error("collapsed key omitted its name or correct status")
		}
		if cards != 2 {
			browserTestForm(t, details, "/settings/api-keys/"+keys[cards].ID+"/revoke")
		} else if len(browserTestElements(details, "form")) != 0 {
			t.Error("revoked key still has a revoke control")
		}
		cards++
	}
	if cards != len(keys) || strings.Contains(page.Body.String(), keys[0].TokenHash) {
		t.Error("key cards missing or private hash exposed")
	}
	if !browserTestHasLink(doc, "/settings/api-keys") {
		t.Error("expanded list omitted the hide-revoked toggle")
	}
	visible := visibleAPIKeys(keys, false)
	if len(visible) != 2 || visible[0].ID != "active" || visible[1].ID != "expired" || len(keys) != 3 {
		t.Fatal("default filtering must hide only revoked keys without changing the source list")
	}
	page = render(pageData{Keys: visible})
	doc = browserTestDocument(t, page)
	if strings.Contains(page.Body.String(), keys[2].Name) || !browserTestHasLink(doc, "/settings/api-keys?show_revoked=1") {
		t.Error("default list exposes a revoked key or lacks the show-revoked toggle")
	}
	if len(browserTestElements(doc, "summary")) != 3 || !strings.Contains(page.Body.String(), "Показано: 2") {
		t.Error("visible key count does not match the filtered list")
	}
	page = render(pageData{Keys: visible, KeySecret: "csp_one-time-test-secret"})
	doc = browserTestDocument(t, page)
	if browserTestInputID(doc, "key-secret") == nil {
		t.Error("one-time secret disappeared")
	}
	for _, details := range browserTestElements(doc, "details") {
		if browserTestInputID(details, "key-secret") != nil {
			t.Error("one-time secret must not be hidden in a disclosure")
		}
	}
	page = render(pageData{})
	if !strings.Contains(page.Body.String(), "disclosure\" open>") {
		t.Error("first key creation should be expanded")
	}
}
