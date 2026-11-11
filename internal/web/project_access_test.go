package web

import (
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"conspect/internal/conspectclient"
	"conspect/internal/store"
)

func TestAPIAllProjectsIncludesFutureResources(t *testing.T) {
	app, db := newTestApp(t)
	original := apiTestProject(t, db, "Original")
	_, restricted := apiTestKey(t, db, store.APIKey{Scopes: []string{"notes:read"}, ProjectIDs: []string{original.ID}})
	allKey, allToken := apiTestKey(t, db, store.APIKey{Scopes: []string{"notes:read", "notes:write"}, AllProjects: true})
	_, noRead := apiTestKey(t, db, store.APIKey{Scopes: []string{"notes:write"}, AllProjects: true})

	server := httptest.NewServer(app.Handler())
	t.Cleanup(server.Close)
	client, err := conspectclient.New(conspectclient.Config{BaseURL: server.URL, APIKey: allToken})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	projects, err := client.ListProjects(t.Context())
	if err != nil || len(projects) != 1 || projects[0].ID != original.ID {
		t.Fatalf("initial projects = %+v, %v", projects, err)
	}

	future := apiTestProject(t, db, "Created after the agent connected")
	futureNote := apiTestNote(t, db, future.ID, "Future note")
	empty := apiTestProject(t, db, "New empty project")
	projects, err = client.ListProjects(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	ids := make([]string, 0, len(projects))
	for _, project := range projects {
		ids = append(ids, project.ID)
	}
	if len(ids) != 3 || !slices.Contains(ids, future.ID) || !slices.Contains(ids, empty.ID) || !slices.Contains(ids, original.ID) {
		t.Fatalf("same agent client did not discover new projects: %v", ids)
	}
	for _, tc := range []struct {
		path  string
		count int
	}{
		{"/api/v1/projects/" + future.ID + "/notes", 1},
		{"/api/v1/projects/" + empty.ID + "/notes", 0},
	} {
		response := apiTestRequest(app, "GET", tc.path, allToken, nil, nil)
		apiTestStatus(t, response, 200)
		result := apiTestDecode[apiTestNoteList](t, response)
		if result.Notes == nil || len(result.Notes) != tc.count {
			t.Fatalf("notes = %+v, want %d entries", result.Notes, tc.count)
		}
		if tc.count > 0 && len(result.Notes[0].Attachments) != 0 {
			t.Error("all-projects grant bypassed attachments:read scope")
		}
	}
	apiTestStatus(t, apiTestRequest(app, "GET", "/api/v1/notes/"+futureNote.ID, allToken, nil, nil), 200)
	apiTestStatus(t, apiTestRequest(app, "GET", "/api/v1/projects/"+store.NewID()+"/notes", allToken, nil, nil), 404)
	apiTestStatus(t, apiTestRequest(app, "POST", "/api/v1/projects/"+empty.ID+"/notes", allToken, strings.NewReader(`{"title":"New note","markdown":"# Markdown"}`), nil), 201)

	response := apiTestRequest(app, "GET", "/api/v1/projects", restricted, nil, nil)
	apiTestStatus(t, response, 200)
	visible := apiTestDecode[apiTestProjectList](t, response)
	if len(visible.Projects) != 1 || visible.Projects[0].ID != original.ID {
		t.Fatalf("restricted key was broadened: %+v", visible.Projects)
	}
	apiTestNoSecrets(t, response, future.ID, futureNote.ID, empty.ID)
	apiTestStatus(t, apiTestRequest(app, "GET", "/api/v1/projects/"+future.ID+"/notes", restricted, nil, nil), 404)
	apiTestStatus(t, apiTestRequest(app, "GET", "/api/v1/notes/"+futureNote.ID, restricted, nil, nil), 404)
	apiTestStatus(t, apiTestRequest(app, "GET", "/api/v1/projects", noRead, nil, nil), 403)
	apiTestStatus(t, apiTestRequest(app, "GET", "/api/v1/notes/"+futureNote.ID, noRead, nil, nil), 403)

	if err := db.UpdateAPIKeyAccess(t.Context(), allKey.ID, false, []string{original.ID}, nil); err != nil {
		t.Fatal(err)
	}
	projects, err = client.ListProjects(t.Context())
	if err != nil || len(projects) != 1 || projects[0].ID != original.ID {
		t.Fatalf("agent did not observe narrowed grants immediately: %+v, %v", projects, err)
	}
	if _, err := client.GetNote(t.Context(), futureNote.ID); err == nil {
		t.Error("agent retained read access after grants were narrowed")
	}
	if err := db.RevokeAPIKey(t.Context(), allKey.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := client.ListProjects(t.Context()); err == nil {
		t.Error("revoked token retained access")
	}
}
