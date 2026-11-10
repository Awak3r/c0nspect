# Conspect — monochrome interface

The user requested a black-and-white redesign guided by [Impeccable](https://github.com/pbakaus/impeccable). The published Operate/Read and craft-floor references informed the implementation; no installer, engine or telemetry was enabled.

## Shipped system

- Grayscale only: no chromatic accents, gradients, decorative shadows or tinted status colors.
- Light: canvas `#ffffff`, secondary surface `#f4f4f4`, text `#191919`, muted text `#595959`, rules `#d0d0d0`, control border `#737373`.
- Dark follows OS preference: canvas `#141414`, secondary `#242424`, text `#eeeeee`, muted text `#b5b5b5`, rules `#484848`, control border `#909090`.
- Login form stays an inverted dark pane; native controls inherit its local tokens.
- System UI typography for operations: body 1rem, secondary .875rem, section 1.25rem, page title 2.5rem. Notes use a 72ch Georgia column at 1.125rem.
- Forms use native inputs, minimum 44px targets, visible focus, explicit invalid/disabled states and textual error/destructive labels.
- Login is a single compact form without an introductory/marketing column. Project browsing uses flat rows with a separate creation sidebar; the sidebar moves beneath content on mobile.
- Personal-tool copy only: headings, labels, status, short empty states and essential operational/security warnings. No slogans, explanatory subtitles, onboarding paragraphs or empty-description placeholders. User-written project descriptions and note contents are preserved.
- Project management shows compact note rows: title, sharing state, modification time and one settings link. Project settings, file import and destructive actions use native disclosures. Individual note forms and attachments live on the owner-only `/notes/{id}/manage` page, not repeated across the project.
- API keys are compact native accordion rows showing only client name and status (active, expired or revoked). Permissions, material grants, dates and revocation controls are collapsed. Revoked keys are excluded from the default response; an explicit show/hide link (`?show_revoked=1`) includes them without restoring access. Expired but non-revoked keys remain visible. Counts reflect the displayed list. Key issuance is collapsed when visible keys exist; the one-time new secret always stays visible outside disclosures.
- Readers retain only document content and ordinary navigation links: no buttons, forms, copy-code controls or action menus.
- Code is monochrome with weight/italics for syntax; mathematical notation stays intact. Uploaded figures retain original colors and information.
- Tables, code and formulas scroll within the reading column. Reduced-motion, forced-colors and print rules are included.

## Implementation

CSS: `internal/web/static/app.css`, embedded by `internal/web/styles.go`. Templates use a content-hashed stylesheet URL, so deploying a design change does not require users to clear a one-day CSS cache. Existing form actions, CSRF protection, permissions, API and MCP behavior are unchanged.

The local Chrome viewport capture was interrupted at the user's request. No completed responsive audit or Impeccable engine verdict is claimed. Compilation and application startup are the deployment checks; the user requested to review the live design directly.
