# Quincho — design

*Quincho supersedes Hefesto (retired 2026-08-17). Hefesto forged; Quincho serves.*

Quincho is governed **build and deploy** for encrypted `devops-*` Docker Swarm
repositories, operated from BullDock. It keeps Hefesto's principles — everything
in memory, docker CLI, images are the build unit and services the deploy unit,
mailed reports, rollback points — and adds what Hefesto never had: an identity
model (SSO + 2FA + Linux credentials + git policy), a UI, an audit store, and a
key model in which **no private key ever exists on the server**.

---

## 1. Components

```
Browser ── Pomerium (Entra SSO) ──▶ BullDock (ZK)                  swarm manager host
                                    ├─ Quincho · Deploy   ─┐  local unix socket   ┌────────────────┐
                                    ├─ Quincho · Build    ─┼── /run/quincho.sock ─▶│ quincho-agent  │─▶ docker CLI
                                    └─ Quincho · History  ─┘                       │ no secrets     │─▶ PAM
                                    holds: git/CI tokens, audit DB (SQLite),        │ at rest        │─▶ tmpfs work dir
                                    brand, mail config                              └────────────────┘
```

| Component | Runs where | Owns |
|---|---|---|
| **quincho-agent** | static Linux binary, systemd service on each swarm manager | execution: PAM auth, policy checks, tmpfs work dir, `docker stack deploy` / `docker build`, log streaming, snapshots. **Holds no secrets at rest.** |
| **BullDock · Quincho tool** | BullDock (systools stack), tabs Deploy · Build · History | identity (SSO email, TOTP), catalog, git/CI tokens (Swarm secrets), audit store, mail, UI |
| **Devops repos** (`devops-<hostname>`) | git | stacks, `deploy.sh`, `.quincho.yml` policy, `build.yml` catalogs |

Engine: the agent starts from `hefesto-core` (Rust): MemFs in-memory repository,
compose folding + `docker stack deploy -c -`, `--resolve-image always`, digest
pins, apply/rollback manifests, inventory, HTML reports. Retired with Hefesto:
the `ed.sh` 1.x AES vault, the terminal picker, the interactive passphrase, the
single build box.

Channel BullDock → agent: JSON over HTTP on a unix socket bind-mounted into the
BullDock service (local only, never a TCP port). Every request carries the
operator identity, the Linux credentials and — for the duration of the request —
whatever material the action needs; the agent zeroizes it afterwards.

---

## 2. Key model — keys only in memory, never on the server

Requirement (owner): *nobody must be able to copy a private/public key and deploy
on another server; if BAT removes my access I must lose nothing.*

Rejected: Azure Key Vault (not owned/managed by us). Optional later: TPM-sealed
key as an *extra* recipient for unattended jobs.

Rule: **`.sops.yaml` recipients are people.** Every deployer holds their own age
key on their own machine; an offline backup key exists (safe). No machine key is
required for a deploy, and no private key is stored on the server or in BullDock.

- **Level 1 (phase 1)** — the deployer supplies their age key at the button; it
  travels over the SSO'd, same-origin TLS session, is used in agent memory only
  and zeroized with the plaintext once the deploy ends.
- **Level 2 (target)** — the repo bundle is decrypted **in the browser** (age in
  JS/WASM, key read locally, never uploaded); only the plaintext files of the
  selected stack travel to BullDock → agent → tmpfs → deploy → shred. The server
  never sees a private key, not even in memory.

Consequences: no unattended deploys (a human with a key and Linux credentials must
be present — a governance feature); revocation = remove recipient + `ed.sh rekey`;
the server's own age key is removed once Quincho is live (break-glass = a human key
+ bastion + `run.sh`).

### Threat model

| Party | Trust | Can |
|---|---|---|
| Deployer with their key | trusted | deploy what policy allows, audited |
| Root on the host | semi-trusted | see what *that host* runs (it does anyway via `docker service inspect`); nothing else — no keys, no other hosts' secrets |
| Anyone with copies of files, backups, Swarm secrets, the repo | untrusted | nothing — there is nothing to decrypt with |

Reducing the residual (root scraping agent memory during a deploy): keys never on
the host (Level 2); only the selected stack's plaintext, seconds long, in locked
memory/tmpfs, then zeroized; Docker secrets rather than env vars for credentials;
`kernel.yama.ptrace_scope=3`, agent as its own user with `PR_SET_DUMPABLE=0`, no
core dumps, `/dev/shm` `noexec,nosuid`; `auditd` on ptrace / `/proc/*/mem` /
`docker secret|service inspect` with logs shipped off-host; few, named roots;
signed agent binary whose hash BullDock verifies before each call.

---

## 3. Governance — who may press the button

Four gates, all required, nothing stored:

| Gate | Answers | Verified by |
|---|---|---|
| Entra SSO | who you are | Pomerium → BullDock identity |
| TOTP step-up | it's you, now — **fresh code at every deploy** | BullDock (existing enrollment; code ≤30 s, single use) |
| Linux user + password | you hold an account on the target host and are in group `quincho` | agent via PAM; used once, never logged/stored |
| Repo policy | this person may deploy/build this repo on this host | `.quincho.yml` in the devops repo |

`.quincho.yml` (encrypted like every other `.yml`, history in git):

```yaml
host: AZCRNRONEVTA01
deployers: { carlos: carlos@ipremios.com, marius: marius@bat.com }   # linux user -> SSO email
builders:  { carlos: carlos@ipremios.com }
approvers: []            # optional four-eyes for PROD hosts
notify:
  deploy:   [platform@ipremios.com]
  build:    [platform@ipremios.com]
  security: [carlos@ipremios.com]
```

Session binding: SSO email, Linux user and TOTP identity must name the same person.
Confirmation is **per plan** (one dialog for a multi-stack plan), not per stack;
read actions (browse, diff, history, inventory) need only the tool unlock.
Optional PROD hardening: second factor enforced by the agent's PAM stack
(`pam_google_authenticator`/`pam_oath`), independent of BullDock.

The agent additionally enforces Hefesto's **host gate**: `devops-<hostname>` must
match the machine, and `.quincho.yml host:` must match too.

---

## 4. Catalogs — what the UIs show

- **Deploy**: catalog `quincho.yml` (Swarm secret next to `bulldock_targets.env`)
  lists the devops repos this BullDock serves and the read-only git tokens.
- **Build**: Hefesto's `build.yml` catalogs of those devops repos (`repoList`:
  image, source repo, branch, tag, destination, mailGroup) — already maintained
  in git; optional extra entries in `quincho.yml`. Builds run by **CI dispatch**
  (GitHub Actions / Azure Pipelines `workflow_dispatch`, status polled) by
  default; agent `docker build` from an in-memory tarball as fallback for repos
  without CI (needs the corporate proxy; burns CPU on the manager).

---

## 5. Deploy sequence

1. Operator opens Quincho (SSO identity, TOTP unlock).
2. Picks repo → branch/commit. Bundle fetched to RAM; decrypted (Level 1: agent
   memory with the supplied key; Level 2: browser). Parse `.quincho.yml`,
   composes, `build.yml`.
3. Picks stack or services. **Snapshot**: for each touched service the agent
   records `image@digest` running, full service spec, current record/commit.
4. Confirmation dialog: the plan (`service: before → after`, same-tag-new-digest
   shown as a change, downgrades flagged), Linux user, password, fresh code.
5. Agent: PAM → group `quincho` → `.quincho.yml` (host, user, email) → private
   tmpfs → runs the stack's `deploy.sh` (phase 1, devops repos untouched) or
   compose-from-memory pinned by digest (phase 2, Hefesto way), `--detach=false`
   → streams logs → shreds → returns `{status, before, after, log}`.
6. BullDock: audit record, History, mail report. On failure to converge: **automatic
   rollback** to the snapshot, record `rolled-back`.

---

## 6. Rollback

- **Automatic**: failed plan → redeploy snapshot; never a half-applied plan.
- **Quick**: result screen button → `docker service update --rollback` (previous
  spec, seconds, one step back).
- **History**: pick a record → "Roll back to this" → redeploy **that commit's
  compose with that record's digests** (config and images of that moment). It is
  a deploy: same confirmation, own record.
- Digests must survive: registry keeps last N digests (retag `<tag>-prev` on each
  build), node prune never removes images referenced by a record; warn before a
  deploy if the rollback digest is not resolvable. Composes should carry
  `update_config: failure_action: rollback, order: start-first`.

---

## 7. Audit store and notifications

**System of record: SQLite** in BullDock's data volume
(`/apps/sysdata/systools/bulldock/quincho/quincho.db`, WAL, append-only tables):

- `deployment(id, ts, host, actor_email, linux_user, repo, commit, stack, kind[deploy|rollback|build], plan_json, status, duration_ms, log_ref, mail_status)`
- `deployment_service(deployment_id, service, image_before, digest_before, image_after, digest_after, spec_before_json)`
- `event(id, ts, actor_email, action, detail_json)` — unlocks, refused attempts, policy denies, agent errors
- logs as `logs/<id>.log.gz` next to the DB.

Off-host copy: **mail now**; **Azure Blob with immutable storage later** (owner
decision: "for the future") — same export, promoted to tamper-proof archive when a
storage account of ours exists.

**Mail** (Hefesto's report, kept): one mail per plan, every outcome, plus security
notices for refused attempts. Recipients from `.quincho.yml notify:` and
`build.yml mailGroups`, actor always in copy. Content: who/when/what, `before →
after` with digests, per-item status, captured log, link to the History record,
brand logo inline (`cid:`). Transport: Microsoft Graph `sendMail` over HTTPS via the
proxy (preferred), Jakarta Mail with `mail.smtp.proxy.host` as fallback.
Best-effort, never blocks a deploy; status stored on the record.

---

## 8. Phases

| Phase | Deliverable |
|---|---|
| 0 | this document; `quincho` repo started from `hefesto-core` (git lineage kept) |
| 1 | agent: unix-socket API, PAM + group + `.quincho.yml`, tmpfs, `deploy.sh` runner, snapshots, log streaming; BullDock Deploy tab (Level 1 key), SQLite audit, mail |
| 2 | Build tab (CI dispatch, agent fallback), History with rollback, quick rollback, compose-from-memory pinned deploys |
| 3 | Level 2 browser-side decryption, approvers (four-eyes), Blob archive, runbook |

## 9. Open decisions

- Deploy contract phase 1: `deploy.sh` per stack (no change to devops repos) — proposed yes.
- Catalog location: `quincho.yml` Swarm secret per BullDock vs a shared `quincho-catalog` repo.
- Four-eyes for PROD hosts.
- When to remove the server's age key from `.sops.yaml` (needs the break-glass procedure written first).
