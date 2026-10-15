# CLAUDE.md

## Search: zg first for concepts, rg for exact strings

For "where/how is X handled" questions use zg first; for exact identifiers use rg; only open files zg or rg points to.

- zg is [zvec-grep](https://github.com/zvec-ai/zvec-grep) 0.2.2, local semantic search: `zg query "<idea>"` (this repo ignores `*.json`, so `.mcp.json` is local: `zg server --stdio --mcp-toolset agent`).
- Local model only: `local/potion-retrieval-32m`. Never pass `--allow-remote` or configure a remote embedding provider.
- The index is per checkout in `.zvec-grep/` (gitignored). Build or refresh it after big changes (branch switch, large merge, new worktree): `zg index . --embedding local/potion-retrieval-32m --ignore-file .zvec-grep-ignore`. It is incremental. With no index, zg returns nothing; use rg.
- Needs `npm i -g @zvec/zvec-grep@0.2.2` (Node >= 22). Exclusions live in `.zvec-grep-ignore`.
