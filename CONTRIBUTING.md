# Contributing

## Setup

```bash
mise install
cargo test
```

Before a pull request, run `cargo fmt --check` and `cargo clippy --all-targets -- -D warnings`. Data formats are described in [internals](docs/internals.md).

## Rules

- Keep the single binary and the no-database design.
- Add a regression test with every security fix.
- UI changes need a real browser check. Rust tests do not see rendering bugs.
- `toProfile()` and `fromProfile()` in `app.js` must stay symmetric.
- New UI text goes through `tr()`, with an English entry in `i18n.js`.
- `validate` forbids, `lint` only warns. Put a new rule in the right one.
- Error messages are matched by the UI for translation. Changing one means updating `i18n.js`.

## Adding a template

Add an entry to `web/static/secret-templates.json` with `id`, `title`, `hint`, `hint_en`, `name`, `description`, `description_en` and `hosts` (or `fields`, `multiline`, `allow_commands` with `exec`, `totp`). The description must show agents how to use the secret. `cargo test --test web secret_templates` validates it. Do not guess API URLs; link the provider's documentation in the pull request.
