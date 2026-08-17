# Quincho

Governed **build and deploy** for encrypted `devops-*` Docker Swarm repositories,
operated from [BullDock](https://github.com/carlos-camponuevo/bulldock).
Supersedes [Hefesto](https://github.com/carlos-camponuevo/rust-hefesto) (retired 2026-08-17).

- `quincho-agent` — static Linux binary on each swarm manager: PAM, git policy,
  tmpfs, docker; **no secrets at rest**.
- BullDock tool — Deploy · Build · History; SSO + fresh 2FA + Linux credentials
  at every deploy; SQLite audit; mailed reports.
- Keys stay with people, in memory only — never on the server.

Start with [docs/DESIGN.md](docs/DESIGN.md).
