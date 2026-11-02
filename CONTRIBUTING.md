# Contributing

## Setup

```bash
mise install
go test -race ./...
```

## Rules

- Keep the single binary and the no-database design.
- Add a regression test with every security fix.
- UI changes need a real browser check. Go tests do not see rendering bugs.
- `toProfile()` and `fromProfile()` in `app.js` must stay symmetric.
- New UI text goes through `tr()`, with an English entry in `i18n.js`.
- `Validate` forbids, `Lint` only warns. Put a new rule in the right one.

## Adding a template

Add an entry to `internal/web/static/catalog.json` with `group`, `title`, `title_en`, `hint`, `hint_en`, `secrets` and `profile`. `go test ./internal/web` validates it. Do not guess API URLs; link the provider's documentation in the pull request.
