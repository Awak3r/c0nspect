package web

import (
	"bytes"
	"html/template"
	"net/http"
	"strings"

	"conspect/internal/store"
)

type pageData struct {
	Title, CSRF, Error, Message, Query, Sort, ShareURL, KeySecret string
	Owner, DocumentHasTitle                                       bool
	QuickShare                                                    bool
	CurrentPage                                                   string
	Projects                                                      []store.Project
	Project                                                       store.Project
	Notes                                                         []store.Note
	Note                                                          store.Note
	Keys                                                          []store.APIKey
	ShowRevoked                                                   bool
	LoginNext, OAuthClientName, OAuthClientID, OAuthRequest       string
	OAuthScopes                                                   []string
	// Content must come from the Markdown renderer, which sanitizes its output.
	Content template.HTML
}

func (a *App) page(w http.ResponseWriter, r *http.Request, status int, templateName string, data pageData) {
	data.CurrentPage = templateName
	data.Owner, data.CSRF = false, ""
	if session, ok := r.Context().Value(sessionKey{}).(store.Session); ok {
		data.Owner, data.CSRF = true, session.CSRFToken
	}
	data.QuickShare = data.Owner && len(data.Notes) != 0 && (templateName == "project" || (templateName == "projects" && data.Query != ""))
	w.Header().Set("Cache-Control", "no-store")

	// Buffer before committing headers: execution errors may follow private output.
	var output bytes.Buffer
	if err := a.templates.ExecuteTemplate(&output, templateName, data); err != nil {
		// Do not expose or log execution errors: they can contain note text or secrets.
		http.Error(w, "Не удалось отобразить страницу", http.StatusInternalServerError)
		return
	}
	if data.QuickShare {
		policy := w.Header().Get("Content-Security-Policy")
		w.Header().Set("Content-Security-Policy", strings.Replace(policy, "connect-src 'none'", "connect-src 'self'", 1))
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(output.Bytes())
}

const pageTemplates = `
{{define "head"}}<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="referrer" content="same-origin">
  <title>{{if .Title}}{{.Title}} · {{end}}Конспект</title>
  <link rel="stylesheet" href="{{stylesheet}}">
  {{if .QuickShare}}<script defer src="/assets/share.js"></script>{{end}}
</head>{{end}}

{{define "header"}}
<a class="skip-link" href="#main">К содержимому</a>
<header class="site-header">
  <div class="shell header-inner">
    <a class="brand" href="{{if .Owner}}/projects{{else}}/login{{end}}"><span class="brand-word">Конспект</span></a>
    {{if .Owner}}
    <nav class="site-nav" aria-label="Главная навигация">
      <a href="/projects"{{if ne .CurrentPage "keys"}} aria-current="page"{{end}}>Проекты</a>
      <a href="/settings/api-keys"{{if eq .CurrentPage "keys"}} aria-current="page"{{end}}>Настройки</a>
    </nav>
    <form method="post" action="/logout">
      <input type="hidden" name="csrf" value="{{.CSRF}}">
      <button class="button-quiet" type="submit">Выйти</button>
    </form>
    {{end}}
  </div>
</header>{{end}}

{{define "notices"}}
{{if .Error}}<div class="notice notice-error" role="alert">{{.Error}}</div>{{end}}
{{if .Message}}<div class="notice" role="status">{{.Message}}</div>{{end}}
{{end}}

{{define "trash-icon"}}<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M4 7h16M9 7V4h6v3m3 0-1 13H7L6 7m4 4v5m4-5v5"/></svg>{{end}}

{{define "note-list"}}
<ul class="note-list">
  {{range .Notes}}
  <li class="note-row">
    <div class="note-row-heading{{if $.Owner}} with-delete{{end}}">
      <a class="item-title" href="/notes/{{.ID}}">{{.Title}}</a>
      {{template "library-date" .UpdatedAt}}
      {{if $.QuickShare}}
      <form class="note-share" method="post" action="/notes/{{.ID}}/share" data-quick-share>
        <input type="hidden" name="csrf" value="{{$.CSRF}}">
        <input type="hidden" name="action" value="create">
        <button type="submit" class="button-quiet share-button" title="Поделиться по ссылке" aria-label="Поделиться по ссылке: {{.Title}}"><span aria-hidden="true">🔗</span></button>
      </form>
      {{end}}
    </div>
    {{if $.QuickShare}}
    <p class="share-status" data-share-status role="status"></p>
    <input class="share-url mono" data-share-url type="text" aria-label="Публичная ссылка: {{.Title}}" readonly hidden spellcheck="false" autocomplete="off">
    {{end}}
    {{if $.Owner}}
    <details class="note-delete" name="delete-note">
      <summary class="delete-toggle" title="Удалить конспект" aria-label="Удалить конспект: {{.Title}}">{{template "trash-icon"}}</summary>
      <form class="stack delete-form" method="post" action="/notes/{{.ID}}/delete">
        <input type="hidden" name="csrf" value="{{$.CSRF}}">
        <input type="hidden" name="version" value="{{.Version}}">
        <p>Конспект «{{.Title}}» и его вложения будут удалены. Если есть публичная ссылка, она перестанет работать.</p>
        <label class="check"><input type="checkbox" name="confirm" value="DELETE" required> <span>Подтверждаю удаление.</span></label>
        <div><button class="button-danger" type="submit">Удалить конспект</button></div>
      </form>
    </details>
    {{end}}
  </li>
  {{else}}
  <li class="empty-state">Конспектов пока нет.</li>
  {{end}}
</ul>{{end}}

{{define "library-date"}}
<time class="item-meta list-date" datetime="{{.UTC.Format "2006-01-02T15:04:05Z"}}" title="Изменено: {{date .}} UTC">{{.UTC.Format "02.01.2006"}}</time>
{{end}}

{{define "library-search"}}
<form class="library-search" role="search" method="get" action="{{if .Project.ID}}/projects/{{.Project.ID}}{{else}}/projects{{end}}">
  <label class="visually-hidden" for="library-query">{{if .Project.ID}}Поиск в проекте{{else}}Поиск по всем конспектам{{end}}</label>
  <input id="library-query" name="q" type="search" value="{{.Query}}" placeholder="{{if .Project.ID}}Поиск в проекте{{else}}Поиск по всем конспектам{{end}}">
  {{if or .Project.ID .Query}}
  <label class="visually-hidden" for="library-sort">Сортировка конспектов</label>
  <select id="library-sort" name="sort">
    <option value="updated"{{if ne .Sort "title"}} selected{{end}}>По обновлению</option>
    <option value="title"{{if eq .Sort "title"}} selected{{end}}>По названию</option>
  </select>
  {{end}}
  <button class="button-quiet" type="submit">Найти</button>
</form>
{{end}}

{{define "login"}}{{template "head" .}}
<body class="auth-page">
{{template "header" .}}
<main class="shell auth-layout" id="main">

  <section class="login-panel" aria-labelledby="login-title">
    <h1 id="login-title">Вход</h1>
    {{template "notices" .}}
    <form class="stack" method="post" action="/login">
      {{if .LoginNext}}<input type="hidden" name="next" value="{{.LoginNext}}">{{end}}
      <div>
        <label for="username">Имя пользователя</label>
        <input id="username" name="username" type="text" autocomplete="username" autocapitalize="none" spellcheck="false" required>
      </div>
      <div>
        <label for="password">Пароль</label>
        <input id="password" name="password" type="password" autocomplete="current-password" required>
      </div>
      <button type="submit">Войти</button>
    </form>

  </section>
</main>
</body>
</html>{{end}}

{{define "projects"}}{{template "head" .}}
<body>
{{template "header" .}}
<main class="shell library-shell" id="main">
  <div class="library-titlebar">
    <h1>Проекты</h1>
    <details class="library-action">
      <summary>Новый проект</summary>
      <form class="stack library-action-form" method="post" action="/projects">
        <input type="hidden" name="csrf" value="{{.CSRF}}">
        <div>
          <label for="project-name">Название</label>
          <input id="project-name" name="name" type="text" maxlength="300" required>
        </div>
        <div>
          <label for="project-description">Описание <span class="optional">(необязательно)</span></label>
          <textarea id="project-description" name="description" rows="3"></textarea>
        </div>
        <div><button type="submit">Создать проект</button></div>
      </form>
    </details>
  </div>
  {{template "notices" .}}
  {{template "library-search" .}}
  {{if .Query}}
  <section class="library-section" aria-labelledby="results-title">
    <div class="section-heading"><h2 id="results-title">Результаты поиска</h2><a class="text-action" href="/projects">Сбросить поиск</a></div>
    {{if .Notes}}{{template "note-list" .}}{{else}}<p class="empty-state">Ничего не найдено.</p>{{end}}
  </section>
  {{else if .Projects}}
  <ul class="project-list">
    {{range .Projects}}
    <li>
      <div class="project-row-main">
        <a class="item-title" href="/projects/{{.ID}}">{{.Name}}</a>
        {{if .Description}}<p class="description">{{.Description}}</p>{{end}}
      </div>
      {{template "library-date" .UpdatedAt}}
    </li>
    {{end}}
  </ul>
  {{else}}
  <p class="empty-state">Проектов пока нет.</p>
  {{end}}
</main>
</body>
</html>{{end}}

{{define "project"}}{{template "head" .}}
<body>
{{template "header" .}}
<main class="shell library-shell" id="main">
  <p class="breadcrumbs"><a href="/projects">← Проекты</a></p>
  <div class="library-titlebar">
    <div class="project-intro">
      <h1>{{.Project.Name}}</h1>
      {{if .Project.Description}}<p class="description library-description">{{.Project.Description}}</p>{{end}}
      <details class="project-delete">
        <summary class="delete-toggle" title="Удалить проект" aria-label="Удалить проект">{{template "trash-icon"}}</summary>
        <form class="stack delete-form" method="post" action="/projects/{{.Project.ID}}/delete">
          <input type="hidden" name="csrf" value="{{.CSRF}}">
          <p>Проект, его конспекты и вложения будут удалены. Публичные ссылки перестанут работать. Отменить удаление нельзя.</p>
          <label class="check"><input type="checkbox" name="confirm" value="DELETE" required> <span>Подтверждаю удаление проекта и всех его материалов.</span></label>
          <div><button class="button-danger" type="submit">Удалить проект</button></div>
        </form>
      </details>
    </div>
    <details class="library-action"{{if not (or .Query .Notes)}} open{{end}}>
      <summary>Импорт .md</summary>
      <form class="stack library-action-form" method="post" action="/projects/{{.Project.ID}}/notes" enctype="multipart/form-data">
        <input type="hidden" name="csrf" value="{{.CSRF}}">
        <div>
          <label for="import-files">Файлы .md (UTF-8)</label>
          <input id="import-files" name="files" type="file" accept=".md,text/markdown" aria-describedby="import-hint" multiple required>
          <p id="import-hint" class="hint">Каждый файл — новый конспект.</p>
        </div>
        <div><button type="submit">Загрузить</button></div>
      </form>
    </details>
  </div>
  {{template "notices" .}}
  <section class="library-section" aria-labelledby="notes-title">
    <h2 id="notes-title">Конспекты</h2>
    {{if or .Query .Notes}}{{template "library-search" .}}{{end}}
    {{if and .Query (not .Notes)}}<p class="empty-state">Ничего не найдено. <a href="/projects/{{.Project.ID}}">Сбросить поиск</a></p>{{else}}{{template "note-list" .}}{{end}}
  </section>
</main>
</body>
</html>{{end}}


{{define "reader"}}<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="referrer" content="no-referrer">
  <title>{{.Note.Title}}</title>
  <link rel="stylesheet" href="{{stylesheet}}">
  <link rel="stylesheet" href="{{readerAsset "katex.min.css"}}">
  <link rel="stylesheet" href="{{readerAsset "syntax.css"}}">
  <script defer src="{{readerAsset "katex.min.js"}}"></script>
  <script defer src="{{readerAsset "reader.js"}}"></script>
</head>
<body class="reader">
<main class="reader-shell">
  {{if .Owner}}
  <nav class="reader-nav" aria-label="Навигация по проектам">
    <a href="/projects/{{.Note.ProjectID}}">← {{.Project.Name}}</a>
  </nav>
  {{end}}
  <article {{if .DocumentHasTitle}}class="reader-document-title" aria-label="{{.Note.Title}}"{{else}}aria-labelledby="note-title"{{end}}>
    {{if not .DocumentHasTitle}}<header class="reader-heading"><h1 id="note-title">{{.Note.Title}}</h1></header>{{end}}
    <div class="markdown">{{.Content}}</div>
  </article>
</main>
</body>
</html>{{end}}

{{define "share"}}{{template "head" .}}
<body>
{{template "header" .}}
<main class="shell narrow" id="main">
  <p class="breadcrumbs"><a href="/projects/{{.Note.ProjectID}}">← К проекту</a></p>
  <div class="page-heading settings-heading">
    <h1>Публичная ссылка</h1>
    <a class="text-action" href="/notes/{{.Note.ID}}">{{.Note.Title}} →</a>
  </div>
  {{template "notices" .}}
  {{if .ShareURL}}
  <div class="settings-divider">
    <p class="muted">По ссылке можно читать этот конспект и смотреть его изображения.</p>
    <label for="share-url">Ссылка для копирования</label>
    <input id="share-url" class="mono" type="text" value="{{.ShareURL}}" readonly spellcheck="false" autocomplete="off">
  </div>
  {{else if not .Message}}
  <p>Чтобы создать ссылку, нажмите 🔗 рядом с конспектом в списке проекта.</p>
  {{end}}
</main>
</body>
</html>{{end}}

{{define "keys"}}{{template "head" .}}
<body>
{{template "header" .}}
<main class="shell settings-shell" id="main">
  <div class="page-heading settings-heading">
    <p class="page-kicker">Настройки · Подключения</p>
    <h1>API-ключи</h1>
  </div>
  {{template "notices" .}}
  {{if .KeySecret}}
  <section class="panel secret-panel" aria-labelledby="secret-title">
    <h2 id="secret-title">Ключ создан — сохраните секрет</h2>
    <p id="secret-hint">Показан только один раз. Сохраните ключ.</p>
    <label for="key-secret">Новый секрет API-ключа</label>
    <input id="key-secret" class="mono" type="text" value="{{.KeySecret}}" readonly spellcheck="false" autocomplete="off" aria-describedby="secret-hint">
  </section>
  {{end}}
  <details class="settings-divider disclosure"{{if not .Keys}} open{{end}}>
    <summary id="issue-title">Выдать API-ключ</summary>
    <form class="stack key-form" method="post" action="/settings/api-keys">
      <input type="hidden" name="csrf" value="{{.CSRF}}">
      <div>
        <label for="key-name">Название клиента</label>
        <input id="key-name" name="name" type="text" maxlength="300" required>
      </div>
      <fieldset aria-describedby="scopes-hint">
        <legend>Разрешения</legend>
        <p class="hint" id="scopes-hint">Чтение и запись — отдельные разрешения.</p>
        <div class="scope-grid">
          <label class="check"><input type="checkbox" name="scopes" value="notes:read"> <span>Читать конспекты <code>notes:read</code></span></label>
          <label class="check"><input type="checkbox" name="scopes" value="notes:write"> <span>Создавать и изменять конспекты <code>notes:write</code></span></label>
          <label class="check"><input type="checkbox" name="scopes" value="attachments:read"> <span>Читать изображения <code>attachments:read</code></span></label>
          <label class="check"><input type="checkbox" name="scopes" value="attachments:write"> <span>Загружать изображения <code>attachments:write</code></span></label>
        </div>
      </fieldset>
      <label class="check"><input type="checkbox" name="all_projects" value="1" aria-describedby="all-projects-hint"> <span>Все текущие и будущие проекты</span></label>
      <p class="hint" id="all-projects-hint">Ключ получит доступ и к материалам проектов, которые вы создадите в будущем.</p>
      <p class="hint" id="access-hint">Для создания конспектов нужен доступ к проекту.</p>
      <div class="form-grid">
        <fieldset aria-describedby="access-hint projects-hint">
          <legend>Доступ к проектам</legend>
          <p class="hint" id="projects-hint">Все текущие и будущие конспекты проекта.</p>
          <div class="choice-list">
            {{range .Projects}}
            <label class="check"><input type="checkbox" name="projects" value="{{.ID}}"> <span>{{.Name}}</span></label>
            {{else}}<p class="muted">Проектов пока нет.</p>{{end}}
          </div>
        </fieldset>
        <fieldset aria-describedby="access-hint notes-hint">
          <legend>Доступ к отдельным конспектам</legend>
          <p class="hint" id="notes-hint">Только выбранные конспекты.</p>
          <div class="choice-list">
            {{range .Notes}}
            <label class="check"><input type="checkbox" name="notes" value="{{.ID}}"> <span>{{.Title}}</span></label>
            {{else}}<p class="muted">Конспектов пока нет.</p>{{end}}
          </div>
        </fieldset>
      </div>
      <div>
        <label for="key-expires">Срок действия <span class="optional">(необязательно)</span></label>
        <input id="key-expires" name="expires" type="date" aria-describedby="expires-hint">
        <p class="hint" id="expires-hint">Пустое поле — бессрочно.</p>
      </div>
      <div><button type="submit">Выдать ключ</button></div>
    </form>
  </details>
  <section class="section" aria-labelledby="keys-title">
    <div class="section-heading">
      <h2 id="keys-title">Выданные ключи</h2>
      <div class="actions">
        <span class="library-total">Показано: {{len .Keys}}</span>
        {{if .ShowRevoked}}<a class="text-action" href="/settings/api-keys">Скрыть отозванные</a>{{else}}<a class="text-action" href="/settings/api-keys?show_revoked=1">Показать отозванные</a>{{end}}
      </div>
    </div>

    <div class="key-list">
    {{range .Keys}}
    <details class="disclosure key-card" name="api-key">
      <summary id="key-{{.ID}}-title"><span class="key-summary"><span class="key-name">{{.Name}}</span><span class="badge">{{if .RevokedAt}}Отозван{{else if and .ExpiresAt (.ExpiresAt.Before now)}}Истёк{{else}}Действует{{end}}</span></span></summary>
      <div class="key-card-body">
      <dl class="key-details">
        <dt>Разрешения</dt><dd>{{if .Scopes}}{{join .Scopes ", "}}{{else}}Не выданы{{end}}</dd>
        <dt>Все текущие и будущие проекты</dt><dd>{{if .AllProjects}}Да{{else}}Нет{{end}}</dd>
        <dt>Проекты (ID)</dt><dd class="mono">{{if .ProjectIDs}}{{join .ProjectIDs ", "}}{{else}}Не выбраны{{end}}</dd>
        <dt>Конспекты (ID)</dt><dd class="mono">{{if .NoteIDs}}{{join .NoteIDs ", "}}{{else}}Не выбраны{{end}}</dd>
        <dt>Создан</dt><dd><time>{{date .CreatedAt}} UTC</time></dd>
        <dt>Срок действия</dt><dd>{{with .ExpiresAt}}До <time>{{date .}} UTC</time>{{else}}Без ограничения{{end}}</dd>
        <dt>Последнее обращение</dt><dd>{{with .LastUsedAt}}<time>{{date .}} UTC</time>{{else}}Ещё не использовался{{end}}</dd>
        {{with .RevokedAt}}<dt>Отозван</dt><dd><time>{{date .}} UTC</time></dd>{{end}}
      </dl>
      {{if and (not .RevokedAt) (or (not .ExpiresAt) (.ExpiresAt.After now))}}
      {{$key := .}}
      <form class="stack key-form" method="post" action="/settings/api-keys/{{.ID}}/access">
        <input type="hidden" name="csrf" value="{{$.CSRF}}">
        <fieldset aria-describedby="key-{{.ID}}-access-hint">
          <legend>Изменить доступ к материалам</legend>
          <label class="check"><input type="checkbox" name="all_projects" value="1"{{if .AllProjects}} checked{{end}}> <span>Все текущие и будущие проекты</span></label>
          <p class="hint" id="key-{{.ID}}-access-hint">При выборе ключ получит доступ и к будущим материалам новых проектов. Разрешения и секрет ключа не изменятся.</p>
          <div class="form-grid">
            <fieldset><legend>Проекты</legend><div class="choice-list">
              {{range $.Projects}}<label class="check"><input type="checkbox" name="projects" value="{{.ID}}"{{if contains $key.ProjectIDs .ID}} checked{{end}}> <span>{{.Name}}</span></label>{{else}}<p class="muted">Проектов пока нет.</p>{{end}}
            </div></fieldset>
            <fieldset><legend>Отдельные конспекты</legend><div class="choice-list">
              {{range $.Notes}}<label class="check"><input type="checkbox" name="notes" value="{{.ID}}"{{if contains $key.NoteIDs .ID}} checked{{end}}> <span>{{.Title}}</span></label>{{else}}<p class="muted">Конспектов пока нет.</p>{{end}}
            </div></fieldset>
          </div>
        </fieldset>
        <div><button type="submit">Сохранить доступ</button></div>
      </form>
      {{end}}
      {{if not .RevokedAt}}
      <form class="key-revoke" method="post" action="/settings/api-keys/{{.ID}}/revoke">
        <input type="hidden" name="csrf" value="{{$.CSRF}}">
        <button class="button-danger" type="submit">Отозвать ключ</button>
      </form>
      {{end}}
      </div>
    </details>
    {{else}}
    <p class="empty-state">Список пуст.</p>
    {{end}}
    </div>
  </section>
</main>
</body>
</html>{{end}}

{{define "oauth-consent"}}{{template "head" .}}
<body>
{{template "header" .}}
<main class="shell narrow" id="main">
  <div class="page-heading settings-heading">
    <p class="page-kicker">Подключения</p>
    <h1>Подключить ChatGPT</h1>
    <p>{{.OAuthClientName}}</p>
    <p class="item-meta">Клиент: <code>{{.OAuthClientID}}</code></p>
  </div>
  {{template "notices" .}}
  <form class="stack" method="post" action="/oauth/authorize">
    <input type="hidden" name="csrf" value="{{.CSRF}}">
    <input type="hidden" name="request" value="{{.OAuthRequest}}">
    <fieldset><legend>Разрешения</legend>
      {{range .OAuthScopes}}<label class="check"><input type="checkbox" name="scopes" value="{{.}}"{{if eq . "notes:read"}} checked{{end}}> <span>{{if eq . "notes:read"}}Читать конспекты{{else if eq . "notes:write"}}Создавать и изменять конспекты{{else if eq . "attachments:read"}}Читать изображения{{else}}Загружать изображения{{end}} <code>{{.}}</code></span></label>{{end}}
    </fieldset>
    <label class="check"><input type="checkbox" name="all_projects" value="1" aria-describedby="oauth-all-projects-hint"> <span>Все текущие и будущие проекты</span></label>
    <p class="hint" id="oauth-all-projects-hint">ChatGPT получит доступ и к материалам проектов, которые вы создадите в будущем.</p>
    <fieldset><legend>Проекты</legend><div class="choice-list">
      {{range .Projects}}<label class="check"><input type="checkbox" name="projects" value="{{.ID}}"> <span>{{.Name}}</span></label>{{else}}<p>Проектов нет.</p>{{end}}
    </div><p class="hint">Включая будущие конспекты выбранных проектов.</p></fieldset>
    <details class="disclosure"><summary>Отдельные конспекты</summary><div class="choice-list">
      {{range .Notes}}<label class="check"><input type="checkbox" name="notes" value="{{.ID}}"> <span>{{.Title}}</span></label>{{else}}<p>Конспектов нет.</p>{{end}}
    </div></details>
    <p class="hint">Выбранные материалы будут передаваться в ChatGPT. Доступ можно отозвать в API-ключах.</p>
    <div class="actions"><button type="submit" name="decision" value="allow">Разрешить</button><button class="button-quiet" type="submit" name="decision" value="deny">Отмена</button></div>
  </form>
</main>
</body>
</html>{{end}}

{{define "error"}}{{template "head" .}}
<body>
{{template "header" .}}
<main class="shell narrow" id="main">
  <section class="panel" aria-labelledby="error-title">
    <h1 id="error-title">{{if .Title}}{{.Title}}{{else}}Ошибка{{end}}</h1>
    {{template "notices" .}}
    {{if .Owner}}<p><a href="/projects">Вернуться к проектам</a></p>{{end}}
  </section>
</main>
</body>
</html>{{end}}
`
