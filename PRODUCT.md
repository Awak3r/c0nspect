# Conspect — product context

Personal, self-hosted storage for study notes. One owner organizes Markdown notes into projects; readers can view one explicitly shared note without seeing the surrounding project. The owner's primary tasks are finding, importing, organizing and reading notes. AI-assisted writing happens through a separate MCP adapter, not a browser editor.

## Confirmed constraints

- The requested visual direction is black and white: grayscale UI, no chromatic accents.
- Owner and public note readers contain no buttons, forms, editors, hover actions or copy-code controls. Ordinary owner navigation links remain.
- Preserve Markdown, mathematical notation, tables, code and original uploaded images. A monochrome interface must not destroy information in diagrams.
- Project and note identifiers, action URLs, CSRF protection, validation, access controls and MCP/API behavior must not change for the redesign.
- Keep familiar native form controls, keyboard access, readable Russian copy and a responsive layout.
- No external fonts, analytics, decorative JS or production CSP exceptions.

## Surface modes

Login, project browsing and management: **Operate**. Individual notes: **Read**. This is a working personal library, not a marketing landing page.

Design guidance: [Impeccable](https://github.com/pbakaus/impeccable), especially its Operate, Read and craft-floor references. The published guidance was read directly; its installer, engine, telemetry and hooks were not installed or executed.
