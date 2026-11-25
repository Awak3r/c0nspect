package web

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"conspect/internal/store"
)

func TestShareFallbackOnlyDisplaysTheCopyableURL(t *testing.T) {
	app := libraryTestApp(t)
	note := store.Note{ID: "note", ProjectID: "project", Title: "Ряды"}
	page := libraryTestPage(t, app, "share", pageData{Note: note, ShareURL: "https://notes.example.test/s/test"}, true)
	input := browserTestInputID(page, "share-url")
	if input == nil || !hasLibraryAttr(input, "readonly") || !browserTestHasLink(page, "/projects/project") || browserTestHasLink(page, "/notes/note/manage") {
		t.Fatal("share page lost the read-only link or back navigation")
	}
	main := browserTestElements(page, "main")[0]
	if browserTestAttr(input, "value") != "https://notes.example.test/s/test" || len(browserTestElements(main, "form")) != 0 || len(browserTestElements(main, "details")) != 0 {
		t.Error("manual copy fallback must only show the current link, without management controls")
	}
}

func TestMinimalInterfaceCopy(t *testing.T) {
	app, err := New(nil, Config{BaseURL: "http://localhost", Secret: make([]byte, 32), DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	project := store.Project{ID: "project", Name: "Мой проект", Description: "Моё описание проекта"}
	note := store.Note{ID: "note", ProjectID: project.ID, Title: "Мой конспект", Version: 1}
	data := pageData{Project: project, Projects: []store.Project{project}, Note: note, Notes: []store.Note{note}}
	for _, name := range []string{"login", "projects", "project", "share", "keys"} {
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
