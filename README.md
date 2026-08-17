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

## Status

- `core/` — engine (from hefesto-core): in-memory repository, **SOPS/age vault**, compose folding, deploy, snapshots, reports. 33 tests.
- `agent/` — `quincho-agent`: unix-socket API (`/health`, `/snapshot`, `/inspect`, `/deploy` as NDJSON stream), PAM + `quincho` group + `.quincho.yml` policy + host gate, tmpfs job dir shredded after each run, no secrets at rest.
- `install/` — systemd unit, PAM service, installer.
- next — BullDock tool (Deploy · Build · History), SQLite audit, mail reports, Level 2 (browser-side decryption).

### Try it locally (no docker needed)

```sh
cargo build && QUINCHO_DEV_PASSWORD=devpass ./target/debug/quincho-agent --socket /tmp/q.sock --work /tmp/qwork --host EVTA01 --group staff
curl -s --unix-socket /tmp/q.sock http://q/health
```
