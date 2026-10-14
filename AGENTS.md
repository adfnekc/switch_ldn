# Agent notes

## Search discipline
- Do NOT use `find`/`ls -R` for source discovery in this repo — use `rg` (ripgrep).
- Use `rg -n <pattern> src tests` or `rg --files -g '*.c'`.
