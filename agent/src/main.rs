//! quincho-agent — governed deploys on a Docker Swarm manager.
//!
//! Listens on a unix socket only (never TCP). Holds no secrets at rest: every
//! request brings the operator identity, Linux credentials and — for its
//! duration — the material it needs. Work happens in a private tmpfs dir and
//! is shredded afterwards. See docs/DESIGN.md.

mod api;
mod auth;
mod policy;
mod runner;

use anyhow::{Context, Result};
use clap::Parser;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Parser, Debug)]
#[command(name = "quincho-agent", version, about)]
struct Args {
    /// Unix socket path (directory is created; socket mode 0660, group = --socket-group)
    #[arg(long, default_value = "/run/quincho/quincho.sock")]
    socket: PathBuf,
    /// Group that may connect to the socket (BullDock's container user must map into it)
    #[arg(long, default_value = "quincho")]
    socket_group: String,
    /// Linux group an operator must belong to (checked with `id -Gn`)
    #[arg(long, default_value = "quincho")]
    group: String,
    /// Memory-backed work dir (must be tmpfs); jobs live in <work>/<id> for seconds
    #[arg(long, default_value = "/dev/shm/quincho")]
    work: PathBuf,
    /// Override the host name used by the host gate / policy (default: system hostname)
    #[arg(long)]
    host: Option<String>,
    /// Optional brand logo (PNG) for reports; customer files never live in this repo
    #[arg(long)]
    logo: Option<String>,
}

pub struct AppState {
    pub host: String,
    pub group: String,
    pub work: PathBuf,
    jobs: AtomicU64,
}

impl AppState {
    fn next_job(&self) -> u64 {
        self.jobs.fetch_add(1, Ordering::SeqCst)
    }
    /// One line per governance-relevant event; the system journal is the audit
    /// sink of the agent (BullDock keeps the richer SQLite record).
    fn audit(&self, op: &api::Operator, action: &str, outcome: &str, detail: &str) {
        self.audit_str(&op.email, &op.linux_user, action, outcome, detail);
    }
    fn audit_str(&self, email: &str, linux_user: &str, action: &str, outcome: &str, detail: &str) {
        tracing::info!(target: "quincho.audit", email, linux_user, action, outcome, detail, "audit");
    }
}

fn harden() {
    #[cfg(target_os = "linux")]
    unsafe {
        // no core dumps, no ptrace/procfs memory access to this process
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
        let rl = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        libc::setrlimit(libc::RLIMIT_CORE, &rl);
        // keep secrets out of swap when the limit allows it (best effort)
        libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE);
    }
    #[cfg(unix)]
    unsafe {
        libc::umask(0o077);
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    harden();
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with_target(true)
        .init();
    let args = Args::parse();
    if let Some(logo) = &args.logo {
        quincho_core::brand::set_logo_from_file(logo);
    }
    let host = args
        .host
        .clone()
        .unwrap_or_else(|| hostname::get().map(|h| h.to_string_lossy().to_string()).unwrap_or_default())
        .split('.')
        .next()
        .unwrap_or_default()
        .to_string();
    let state = Arc::new(AppState { host: host.clone(), group: args.group.clone(), work: args.work.clone(), jobs: AtomicU64::new(1) });

    if let Some(dir) = args.socket.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    let _ = std::fs::remove_file(&args.socket);
    let listener = tokio::net::UnixListener::bind(&args.socket).with_context(|| format!("binding {}", args.socket.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&args.socket, std::fs::Permissions::from_mode(0o660))?;
        // chgrp to the socket group when it exists (root-only operation; ignore failures on dev boxes)
        let _ = tokio::process::Command::new("chgrp").arg(&args.socket_group).arg(&args.socket).status().await;
    }
    tracing::info!(host, socket = %args.socket.display(), work = %args.work.display(), group = args.group, "quincho-agent ready");
    let app = api::router(state);
    let shutdown = async {
        let _ = tokio::signal::ctrl_c().await;
        tracing::info!("shutting down");
    };
    axum::serve(listener, app).with_graceful_shutdown(shutdown).await?;
    let _ = std::fs::remove_file(&args.socket);
    Ok(())
}
