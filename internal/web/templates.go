package web

import (
	"bytes"
	"html/template"
	"net/http"

	"conspect/internal/store"
)

type pageData struct {
	Title, CSRF, Error, Message, Query, Sort, ShareURL, KeySecret string
	Owner                                                         bool
	ShareActive                                                   bool
	CurrentPage                                                   string
	Projects                                                      []store.Project
	Project                                                       store.Project
	Notes                                                         []store.Note
	Entries                                                       []noteEntry
	Note                                                          store.Note
	Keys                                                          []store.APIKey
	// Content must come from the Markdown renderer, which sanitizes its output.
	Content template.HTML
}

type noteEntry struct {
	Note        store.Note
	Attachments []imageEntry
	Warnings    []string
}

type imageEntry struct {
	Attachment store.Attachment
	Markdown   string
}

func (a *App) page(w http.ResponseWriter, r *http.Request, status int, templateName string, data pageData) {
	data.CurrentPage = templateName
	data.Owner, data.CSRF = false, ""
	if session, ok := r.Context().Value(sessionKey{}).(store.Session); ok {
		data.Owner, data.CSRF = true, session.CSRFToken
	}
	w.Header().Set("Cache-Control", "no-store")

	// Buffer before committing headers: execution errors may follow private output.
	var output bytes.Buffer
	if err := a.templates.ExecuteTemplate(&output, templateName, data); err != nil {
		// Do not expose or log execution errors: they can contain note text or secrets.
		http.Error(w, "Не удалось отобразить страницу", http.StatusInternalServerError)
		return
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
</head>{{end}}

{{define "header"}}
<a class="skip-link" href="#main">К содержимому</a>
<header class="site-header">
  <div class="shell header-inner">
    <a class="brand" href="{{if .Owner}}/projects{{else}}/login{{end}}"><span class="brand-word">Конспект</span></a>
    {{if .Owner}}
    <nav class="site-nav" aria-label="Главная навигация">
      <a href="/projects"{{if ne .CurrentPage "keys"}} aria-current="page"{{end}}>Проекты</a>
      <a href="/settings/api-keys"{{if eq .CurrentPage "keys"}} aria-current="page"{{end}}>API-ключи</a>
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

{{define "note-list"}}
<ul class="note-list">
  {{range .}}
  <li>
    <a class="item-title" href="/notes/{{.ID}}">{{.Title}}</a>
    <span class="item-meta">Изменён <time>{{date .UpdatedAt}} UTC</time></span>
  </li>
  {{else}}
  <li class="empty-state">Конспектов пока нет.</li>
  {{end}}
</ul>{{end}}

{{define "login"}}{{template "head" .}}
<body class="auth-page">
{{template "header" .}}
<main class="shell auth-layout" id="main">

  <section class="login-panel" aria-labelledby="login-title">
    <h1 id="login-title">Вход</h1>
    {{template "notices" .}}
    <form class="stack" method="post" action="/login">
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
<main class="shell" id="main">
  <div class="page-heading library-heading">
    <h1>Проекты</h1>
    <span class="library-total">Всего проектов: {{len .Projects}}</span>
  </div>
  {{template "notices" .}}
  <div class="library-layout">
    <div class="library-main">
  <section class="search-panel" aria-labelledby="search-title">
    <h2 id="search-title">Поиск конспектов</h2>
    <form class="filter-bar" role="search" method="get" action="/projects">
      <div class="grow">
        <label for="query">Заголовок или текст</label>
        <input id="query" name="q" type="search" value="{{.Query}}" placeholder="Найти в своих конспектах">
      </div>
      <div>
        <label for="search-sort">Сортировка</label>
        <select id="search-sort" name="sort">
          <option value="updated"{{if ne .Sort "title"}} selected{{end}}>Сначала обновлённые</option>
          <option value="title"{{if eq .Sort "title"}} selected{{end}}>По названию</option>
        </select>
      </div>
      <button type="submit">Найти</button>
    </form>
    {{if or .Query .Notes}}
    <h3>Результаты поиска</h3>
    {{if .Notes}}{{template "note-list" .Notes}}{{else}}<p class="empty-state">Ничего не найдено.</p>{{end}}
    {{end}}
  </section>
  <section class="section" aria-labelledby="projects-title">
    <div class="section-heading"><h2 id="projects-title">Все проекты</h2></div>
    <div class="project-grid">
      {{range .Projects}}
      <article class="project-card">
        <div class="project-card-main">
          <h3><a href="/projects/{{.ID}}">{{.Name}}</a></h3>
          {{if .Description}}<p class="description">{{.Description}}</p>{{end}}
        </div>
        <p class="item-meta">Обновлён <time>{{date .UpdatedAt}} UTC</time></p>
      </article>
      {{else}}
      <p class="empty-state">Проектов нет.</p>
      {{end}}
    </div>
  </section>
    </div>
  <aside class="library-compose" aria-labelledby="create-project-title">
    <h2 id="create-project-title">Новый проект</h2>

    <form class="stack" method="post" action="/projects">
      <input type="hidden" name="csrf" value="{{.CSRF}}">
      <div>
        <label for="project-name">Название</label>
        <input id="project-name" name="name" type="text" maxlength="300" required>
      </div>
      <div>
        <label for="project-description">Описание <span class="optional">(необязательно)</span></label>
        <textarea id="project-description" name="description" rows="3"></textarea>
      </div>
      <button type="submit">Создать проект</button>
    </form>
  </aside>
  </div>
</main>
</body>
</html>{{end}}

{{define "project"}}{{template "head" .}}
<body>
{{template "header" .}}
<main class="shell" id="main">
  <p class="breadcrumbs"><a href="/projects">Все проекты</a></p>
  <div class="page-heading">
    <h1>{{.Project.Name}}</h1>
    {{if .Project.Description}}<p class="description">{{.Project.Description}}</p>{{end}}
    <p><a href="/projects/{{.Project.ID}}/manage">Управление проектом</a></p>
  </div>
  {{template "notices" .}}
  <section class="panel" aria-labelledby="notes-title">
    <h2 id="notes-title">Конспекты</h2>
    <form class="filter-bar" role="search" method="get" action="/projects/{{.Project.ID}}">
      <div class="grow">
        <label for="project-query">Поиск по заголовку и тексту</label>
        <input id="project-query" name="q" type="search" value="{{.Query}}">
      </div>
      <div>
        <label for="note-sort">Сортировка</label>
        <select id="note-sort" name="sort">
          <option value="updated"{{if ne .Sort "title"}} selected{{end}}>Сначала обновлённые</option>
          <option value="title"{{if eq .Sort "title"}} selected{{end}}>По названию</option>
        </select>
      </div>
      <button type="submit">Показать</button>
    </form>
    {{if and .Query (not .Notes)}}<p class="empty-state">Ничего не найдено.</p>{{else}}{{template "note-list" .Notes}}{{end}}
  </section>
</main>
</body>
</html>{{end}}

{{define "manage"}}{{template "head" .}}
<body>
{{template "header" .}}
<main class="shell" id="main">
  <p class="breadcrumbs"><a href="/projects">Все проекты</a> / <a href="/projects/{{.Project.ID}}">Оглавление проекта</a></p>
  <div class="page-heading">
    <h1>{{.Project.Name}}</h1>

  </div>
  {{template "notices" .}}
  <div class="form-grid">
    <details class="panel disclosure">
      <summary id="edit-project-title">Сведения о проекте</summary>
      <form class="stack" method="post" action="/projects/{{.Project.ID}}/edit">
        <input type="hidden" name="csrf" value="{{.CSRF}}">
        <div>
          <label for="edit-project-name">Название</label>
          <input id="edit-project-name" name="name" type="text" value="{{.Project.Name}}" maxlength="300" required>
        </div>
        <div>
          <label for="edit-project-description">Описание <span class="optional">(необязательно)</span></label>
          <textarea id="edit-project-description" name="description" rows="3">{{.Project.Description}}</textarea>
        </div>
        <div><button type="submit">Сохранить проект</button></div>
      </form>
    </details>
    <details class="panel disclosure"{{if not .Notes}} open{{end}}>
      <summary id="import-title">Загрузить конспекты</summary>
      <p id="import-hint" class="hint">Каждый файл — новый конспект.</p>
      <form class="stack" method="post" action="/projects/{{.Project.ID}}/notes" enctype="multipart/form-data">
        <input type="hidden" name="csrf" value="{{.CSRF}}">
        <div>
          <label for="import-files">Файлы .md (UTF-8)</label>
          <input id="import-files" name="files" type="file" accept=".md,text/markdown" aria-describedby="import-hint" multiple required>
        </div>
        <div><button type="submit">Загрузить файлы</button></div>
      </form>
    </details>
  </div>
  <section class="section" aria-labelledby="manage-notes-title">
    <div class="section-heading"><h2 id="manage-notes-title">Конспекты</h2><span class="library-total">Всего: {{len .Notes}}</span></div>
    <ul class="note-list managed-notes">
      {{range .Notes}}
      <li class="managed-note">
        <div class="managed-note-main">
          <a class="item-title" href="/notes/{{.ID}}">{{.Title}}</a>
          <p class="item-meta">{{if .Shared}}Доступен по ссылке{{else}}Только для вас{{end}} · <time>{{date .UpdatedAt}} UTC</time></p>
        </div>
        <a class="note-settings-link" href="/notes/{{.ID}}/manage" aria-label="Настроить конспект «{{.Title}}»">Настроить</a>
      </li>
      {{else}}
      <li class="empty-state">Конспектов нет.</li>
      {{end}}
    </ul>
  </section>
  <details class="panel disclosure danger-zone section">
    <summary id="delete-project-title">Удалить проект</summary>
    <p>Будет удалён проект, все его конспекты ({{len .Notes}}) и их вложения. Отменить это действие нельзя.</p>
    <form class="stack" method="post" action="/projects/{{.Project.ID}}/delete">
      <input type="hidden" name="csrf" value="{{.CSRF}}">
      <label class="check"><input type="checkbox" name="confirm" value="DELETE" required> <span>Подтверждаю удаление проекта со всеми материалами и отключение их ссылок доступа.</span></label>
      <div><button class="button-danger" type="submit">Удалить проект и материалы</button></div>
    </form>
  </details>
</main>
</body>
</html>{{end}}

{{define "manage-note"}}{{template "head" .}}
<body>
{{template "header" .}}
<main class="shell" id="main">
  <p class="breadcrumbs"><a href="/projects/{{.Project.ID}}/manage">{{.Project.Name}} · Управление проектом</a></p>
  <div class="page-heading"><h1>{{.Note.Title}}</h1></div>
  {{template "notices" .}}
    {{range .Entries}}
    {{$note := .Note}}
    <article class="panel note-management" aria-labelledby="note-{{$note.ID}}-title">
      <div class="note-heading">
        <h2 id="note-{{$note.ID}}-title">Сведения и файлы</h2>
        <p class="item-meta">Версия {{$note.Version}} · Изменён <time>{{date $note.UpdatedAt}} UTC</time></p>
                {{if $note.Shared}}<p class="notice">Доступен по ссылке. Замена файла и правки через MCP сразу станут видны читателям.</p>{{else}}<p class="muted">Публичный доступ закрыт.</p>{{end}}
                {{if .Warnings}}<div class="notice notice-error" role="status"><strong>Не все изображения доступны:</strong><ul>{{range .Warnings}}<li>{{.}}</li>{{end}}</ul></div>{{end}}
        <nav class="actions" aria-label="Страницы конспекта">
          <a href="/notes/{{$note.ID}}">Читать конспект</a>
          <a href="/notes/{{$note.ID}}/share">Доступ по ссылке</a>
        </nav>
      </div>
      <div class="form-grid">
        <section aria-labelledby="metadata-{{$note.ID}}">
          <h4 id="metadata-{{$note.ID}}">Название и расположение</h4>
          <form class="stack" method="post" action="/notes/{{$note.ID}}/metadata">
            <input type="hidden" name="csrf" value="{{$.CSRF}}">
            <input type="hidden" name="version" value="{{$note.Version}}">
            <div>
              <label for="title-{{$note.ID}}">Заголовок</label>
              <input id="title-{{$note.ID}}" name="title" type="text" value="{{$note.Title}}" maxlength="300" required>
            </div>
            <div>
              <label for="project-{{$note.ID}}">Проект</label>
              <select id="project-{{$note.ID}}" name="project_id" required>
                {{range $.Projects}}<option value="{{.ID}}"{{if eq .ID $note.ProjectID}} selected{{end}}>{{.Name}}</option>{{else}}<option value="{{$note.ProjectID}}">{{$.Project.Name}}</option>{{end}}
              </select>
            </div>
            <div><button type="submit">Сохранить сведения</button></div>
          </form>
        </section>
        <section aria-labelledby="replace-{{$note.ID}}">
          <h4 id="replace-{{$note.ID}}">Заменить Markdown</h4>
          <p class="muted" id="replace-hint-{{$note.ID}}">Адрес, вложения и ссылка доступа сохраняются.</p>
          <form class="stack" method="post" action="/notes/{{$note.ID}}/replace" enctype="multipart/form-data">
            <input type="hidden" name="csrf" value="{{$.CSRF}}">
            <input type="hidden" name="version" value="{{$note.Version}}">
            <div>
              <label for="replace-file-{{$note.ID}}">Новый файл .md в UTF-8</label>
              <input id="replace-file-{{$note.ID}}" name="file" type="file" accept=".md,text/markdown" aria-describedby="replace-hint-{{$note.ID}}" required>
            </div>
            <div><button type="submit">Заменить файл</button></div>
          </form>
        </section>
      </div>
      <details class="subsection disclosure"{{if .Warnings}} open{{end}}>
        <summary id="images-{{$note.ID}}">Изображения · {{len .Attachments}}</summary>
        <p id="image-hint-{{$note.ID}}" class="muted">Загрузка не вставляет изображение в текст. Добавьте Markdown-фрагмент отдельно.</p>
        <form class="stack" method="post" action="/notes/{{$note.ID}}/attachments" enctype="multipart/form-data">
          <input type="hidden" name="csrf" value="{{$.CSRF}}">
          <div>
            <label for="image-file-{{$note.ID}}">Изображение PNG, JPEG или WebP</label>
            <input id="image-file-{{$note.ID}}" name="file" type="file" accept="image/png,image/jpeg,image/webp" aria-describedby="image-hint-{{$note.ID}}" required>
          </div>
          <div><button type="submit">Загрузить изображение</button></div>
        </form>
        <ul class="attachment-list">
          {{range .Attachments}}
          <li class="attachment">
            <p><a href="/notes/{{$note.ID}}/attachments/{{.Attachment.ID}}">{{.Attachment.Name}}</a> <span class="item-meta">{{.Attachment.Size}} байт</span></p>
            <label for="markdown-{{.Attachment.ID}}">Markdown-фрагмент для исходника</label>
            <input id="markdown-{{.Attachment.ID}}" class="mono" type="text" value="{{.Markdown}}" readonly spellcheck="false" autocomplete="off">
            <form class="stack compact-form" method="post" action="/notes/{{$note.ID}}/attachments/{{.Attachment.ID}}/delete">
              <input type="hidden" name="csrf" value="{{$.CSRF}}">
              <label class="check"><input type="checkbox" name="confirm" value="DELETE" required> <span>Подтверждаю удаление изображения. Ссылки на него в тексте перестанут работать.</span></label>
              <div><button class="button-danger" type="submit">Удалить изображение</button></div>
            </form>
          </li>
          {{else}}
          <li class="muted">Изображений пока нет.</li>
          {{end}}
        </ul>
      </details>
      <details class="danger-zone subsection disclosure">
        <summary id="delete-note-{{$note.ID}}">Удалить конспект</summary>
        <form class="stack" method="post" action="/notes/{{$note.ID}}/delete">
          <input type="hidden" name="csrf" value="{{$.CSRF}}">
          <input type="hidden" name="version" value="{{$note.Version}}">
          <label class="check"><input type="checkbox" name="confirm" value="DELETE" required> <span>Подтверждаю удаление этого конспекта со всеми вложениями. Ссылка доступа перестанет работать.</span></label>
          <div><button class="button-danger" type="submit">Удалить конспект</button></div>
        </form>
      </details>
    </article>
    {{end}}
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
  <link rel="stylesheet" href="/assets/reader/katex.min.css">
  <link rel="stylesheet" href="/assets/reader/syntax.css">
  <script defer src="/assets/reader/katex.min.js"></script>
  <script defer src="/assets/reader/reader.js"></script>
</head>
<body class="reader">
<main class="reader-shell">
  {{if .Owner}}
  <nav class="reader-nav" aria-label="Навигация по проектам">
    <a href="/projects">Проекты</a>
    <a href="/projects/{{.Note.ProjectID}}">К оглавлению проекта</a>
  </nav>
  {{end}}
  <article aria-labelledby="note-title">
    <header class="reader-heading"><h1 id="note-title">{{.Note.Title}}</h1></header>
    <div class="markdown">{{.Content}}</div>
  </article>
</main>
</body>
</html>{{end}}

{{define "share"}}{{template "head" .}}
<body>
{{template "header" .}}
<main class="shell narrow" id="main">
  <p class="breadcrumbs"><a href="/projects/{{.Note.ProjectID}}/manage">Управление проектом</a></p>
  <div class="page-heading">
    <h1>Доступ по ссылке</h1>
    <p>{{.Note.Title}}</p>
    <p><a href="/notes/{{.Note.ID}}">Читать конспект</a></p>
  </div>
  {{template "notices" .}}
  <section class="panel" aria-labelledby="share-title">
    <h2 id="share-title">Ссылка только для чтения</h2>
    <p class="muted">Конспект и изображения доступны всем, у кого есть ссылка. Остальные материалы закрыты.</p>
    {{if .ShareActive}}
    {{if .ShareURL}}
    <label for="share-url">Текущая ссылка</label>
    <input id="share-url" class="mono" type="text" value="{{.ShareURL}}" readonly spellcheck="false" autocomplete="off">

    {{end}}
    <div class="subsection">
      <h3>Перевыпустить ссылку</h3>
      <p class="muted">Старая ссылка сразу перестанет работать.</p>
      <form method="post" action="/notes/{{.Note.ID}}/share">
        <input type="hidden" name="csrf" value="{{.CSRF}}">
        <input type="hidden" name="action" value="rotate">
        <button type="submit">Перевыпустить ссылку</button>
      </form>
    </div>
    <div class="danger-zone subsection">
      <h3>Отключить доступ</h3>
      <p>Ссылка перестанет работать. Конспект не удаляется.</p>
      <form method="post" action="/notes/{{.Note.ID}}/share">
        <input type="hidden" name="csrf" value="{{.CSRF}}">
        <input type="hidden" name="action" value="revoke">
        <button class="button-danger" type="submit">Отозвать ссылку</button>
      </form>
    </div>
    {{else}}
    <p class="empty-state">Доступ по ссылке отключён.</p>
    <form method="post" action="/notes/{{.Note.ID}}/share">
      <input type="hidden" name="csrf" value="{{.CSRF}}">
      <input type="hidden" name="action" value="create">
      <button type="submit">Создать ссылку</button>
    </form>
    {{end}}
  </section>
</main>
</body>
</html>{{end}}

{{define "keys"}}{{template "head" .}}
<body>
{{template "header" .}}
<main class="shell" id="main">
  <div class="page-heading">
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
  <details class="panel section disclosure"{{if not .Keys}} open{{end}}>
    <summary id="issue-title">Выдать API-ключ</summary>
    <form class="stack" method="post" action="/settings/api-keys">
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
    <div class="section-heading"><h2 id="keys-title">Выданные ключи</h2><span class="library-total">Всего: {{len .Keys}}</span></div>

    <div class="key-list">
    {{range .Keys}}
    <details class="disclosure key-card" name="api-key">
      <summary id="key-{{.ID}}-title"><span class="key-summary"><span class="key-name">{{.Name}}</span><span class="badge">{{if .RevokedAt}}Отозван{{else if and .ExpiresAt (.ExpiresAt.Before now)}}Истёк{{else}}Действует{{end}}</span></span></summary>
      <div class="key-card-body">
      <dl class="key-details">
        <dt>Разрешения</dt><dd>{{if .Scopes}}{{join .Scopes ", "}}{{else}}Не выданы{{end}}</dd>
        <dt>Проекты (ID)</dt><dd class="mono">{{if .ProjectIDs}}{{join .ProjectIDs ", "}}{{else}}Не выбраны{{end}}</dd>
        <dt>Конспекты (ID)</dt><dd class="mono">{{if .NoteIDs}}{{join .NoteIDs ", "}}{{else}}Не выбраны{{end}}</dd>
        <dt>Создан</dt><dd><time>{{date .CreatedAt}} UTC</time></dd>
        <dt>Срок действия</dt><dd>{{with .ExpiresAt}}До <time>{{date .}} UTC</time>{{else}}Без ограничения{{end}}</dd>
        <dt>Последнее обращение</dt><dd>{{with .LastUsedAt}}<time>{{date .}} UTC</time>{{else}}Ещё не использовался{{end}}</dd>
        {{with .RevokedAt}}<dt>Отозван</dt><dd><time>{{date .}} UTC</time></dd>{{end}}
      </dl>
      {{if not .RevokedAt}}
      <form method="post" action="/settings/api-keys/{{.ID}}/revoke">
        <input type="hidden" name="csrf" value="{{$.CSRF}}">
        <button class="button-danger" type="submit">Отозвать ключ</button>
      </form>
      {{end}}
      </div>
    </details>
    {{else}}
    <p class="empty-state">Ключей нет.</p>
    {{end}}
    </div>
  </section>
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
