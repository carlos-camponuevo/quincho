//! HTTP API over the unix socket. Every mutating call carries the operator's
//! identity, Linux credentials and — for the duration of the call — whatever
//! secret material it needs. Responses to long jobs are NDJSON event streams.
//!
//! GET  /health              -> { host, version, docker }
//! POST /snapshot            { stack, services? }                       -> { services: {name: {image, spec}} }
//! POST /deploy              see DeployRequest                          -> NDJSON stream of runner::Event
//! POST /inspect             { age_identity?, bundle }                  -> { files, policy, recipients }  (dry run of the vault)

use crate::policy::{Action, Policy, host_gate};
use crate::runner::{Event, Job, ServiceImage};
use crate::{auth, AppState};
use anyhow::{Context, Result, anyhow, bail};
use axum::{
    Json, Router,
    body::Body,
    extract::State,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::Engine;
use quincho_core::sops::Identity;
use quincho_core::vault::MemFs;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use zeroize::Zeroizing;

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/snapshot", post(snapshot))
        .route("/inspect", post(inspect))
        .route("/deploy", post(deploy))
        .with_state(state)
}

// ------------------------------------------------------------------ types

#[derive(Deserialize)]
pub struct Operator {
    pub email: String,
    pub linux_user: String,
}

/// Bundle: repo-relative path -> base64 content. Entries ending in `.sops` are
/// decrypted with `age_identity` (Level 1); plaintext entries are used as-is
/// (Level 2: decrypted in the browser).
#[derive(Deserialize)]
pub struct DeployRequest {
    pub operator: Operator,
    pub password: String,
    pub repo: String,
    #[serde(default)]
    pub commit: String,
    pub stack: String,
    #[serde(default)]
    pub services: Vec<String>,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub age_identity: Option<String>,
    pub bundle: BTreeMap<String, String>,
}

#[derive(Deserialize)]
pub struct SnapshotRequest {
    pub stack: String,
    #[serde(default)]
    pub services: Vec<String>,
}

#[derive(Deserialize)]
pub struct InspectRequest {
    #[serde(default)]
    pub age_identity: Option<String>,
    pub bundle: BTreeMap<String, String>,
}

#[derive(Serialize)]
pub struct ApiError {
    pub error: String,
}

fn err(status: StatusCode, e: impl std::fmt::Display) -> Response {
    (status, Json(ApiError { error: e.to_string() })).into_response()
}

// --------------------------------------------------------------- handlers

async fn health(State(s): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let docker = tokio::process::Command::new("docker")
        .args(["info", "--format", "{{.Swarm.LocalNodeState}} {{.Swarm.ControlAvailable}}"])
        .output()
        .await
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "unavailable".into());
    Json(serde_json::json!({
        "host": s.host, "version": env!("CARGO_PKG_VERSION"), "docker": docker, "group": s.group,
    }))
}

async fn snapshot(Json(req): Json<SnapshotRequest>) -> Response {
    match crate::runner::snapshot(&req.stack, &req.services).await {
        Ok(services) => Json(serde_json::json!({ "services": services })).into_response(),
        Err(e) => err(StatusCode::BAD_GATEWAY, e),
    }
}

/// Decode + (optionally) decrypt the bundle into memory. Returns the vault and the
/// stack policy if `.quincho.yml` is present.
fn open_bundle(bundle: &BTreeMap<String, String>, age_identity: Option<&str>) -> Result<(MemFs, Option<Policy>)> {
    let b64 = base64::engine::general_purpose::STANDARD;
    let mut fs = MemFs::default();
    for (path, data) in bundle {
        let clean = crate::runner::normalize(path)?;
        fs.files.insert(clean, b64.decode(data).with_context(|| format!("bundle entry '{path}' is not base64"))?);
    }
    let has_sops = fs.files.keys().any(|k| k.ends_with(".sops"));
    if has_sops {
        let secret = age_identity.ok_or_else(|| anyhow!("bundle contains encrypted files but no age_identity was supplied"))?;
        let id = Identity::parse(Zeroizing::new(secret.to_string()))?;
        fs.decrypt_sops(&id)?;
    }
    let policy = match fs.get(".quincho.yml") {
        Some(y) => Some(Policy::parse(y).context("parsing .quincho.yml")?),
        None => None,
    };
    Ok((fs, policy))
}

async fn inspect(Json(req): Json<InspectRequest>) -> Response {
    let recipients: Vec<String> = {
        let b64 = base64::engine::general_purpose::STANDARD;
        let mut fs = MemFs::default();
        for (p, d) in &req.bundle {
            if let (Ok(c), Ok(b)) = (crate::runner::normalize(p), b64.decode(d)) {
                fs.files.insert(c, b);
            }
        }
        fs.sops_recipients()
    };
    match open_bundle(&req.bundle, req.age_identity.as_deref()) {
        Ok((fs, policy)) => Json(serde_json::json!({
            "files": fs.files.keys().collect::<Vec<_>>(),
            "policy": policy.map(|p| serde_json::json!({"host": p.host, "deployers": p.deployers.keys().collect::<Vec<_>>(), "builders": p.builders.keys().collect::<Vec<_>>()})),
            "recipients": recipients,
        }))
        .into_response(),
        Err(e) => err(StatusCode::UNPROCESSABLE_ENTITY, e),
    }
}

/// The deploy: gates first (nothing touches disk before all of them pass), then
/// snapshot, then `deploy.sh` in tmpfs with a streamed log, then shred.
async fn deploy(State(s): State<Arc<AppState>>, Json(mut req): Json<DeployRequest>) -> Response {
    let password = Zeroizing::new(std::mem::take(&mut req.password));
    let identity = req.age_identity.take().map(Zeroizing::new);

    // ---- gates (synchronous, before any work) ----
    if let Err(e) = host_gate(&req.repo, &s.host) {
        s.audit(&req.operator, "deploy", "refused", &e.to_string());
        return err(StatusCode::FORBIDDEN, e);
    }
    if let Err(e) = auth::in_group(&req.operator.linux_user, &s.group).await {
        s.audit(&req.operator, "deploy", "refused", &e.to_string());
        return err(StatusCode::FORBIDDEN, e);
    }
    let user = req.operator.linux_user.clone();
    let pw = password.clone();
    let pam = tokio::task::spawn_blocking(move || auth::pam_authenticate(&user, &pw)).await;
    if let Err(e) = pam.unwrap_or_else(|e| Err(anyhow!("pam task: {e}"))) {
        s.audit(&req.operator, "deploy", "refused", "pam");
        return err(StatusCode::UNAUTHORIZED, e);
    }
    let (fs, policy) = match open_bundle(&req.bundle, identity.as_deref().map(|z| z.as_str())) {
        Ok(x) => x,
        Err(e) => {
            s.audit(&req.operator, "deploy", "refused", &e.to_string());
            return err(StatusCode::UNPROCESSABLE_ENTITY, e);
        }
    };
    drop(identity);
    let policy = match policy {
        Some(p) => p,
        None => {
            s.audit(&req.operator, "deploy", "refused", "no .quincho.yml");
            return err(StatusCode::FORBIDDEN, "repository has no .quincho.yml — deploys through Quincho are not enabled for it");
        }
    };
    if let Err(e) = policy.authorize(Action::Deploy, &s.host, &req.operator.linux_user, &req.operator.email) {
        s.audit(&req.operator, "deploy", "refused", &e.to_string());
        return err(StatusCode::FORBIDDEN, e);
    }
    s.audit(&req.operator, "deploy", "start", &format!("{} {} {}", req.repo, req.commit, req.stack));

    // ---- streamed execution ----
    let (tx, rx) = mpsc::channel::<Event>(256);
    let state = s.clone();
    let stack = req.stack.clone();
    let services = req.services.clone();
    let args = req.args.clone();
    let operator_email = req.operator.email.clone();
    let operator_user = req.operator.linux_user.clone();
    let files = fs.files;
    tokio::spawn(async move {
        let send = |e: Event| { let tx = tx.clone(); async move { let _ = tx.send(e).await; } };
        // stack name as swarm sees it: rouat/data -> rouat-data (Hefesto convention)
        let swarm_stack = stack.replace('/', "-");
        send(Event::Info { message: format!("snapshot of stack {swarm_stack}") }).await;
        let before: BTreeMap<String, ServiceImage> = match crate::runner::snapshot(&swarm_stack, &services).await {
            Ok(m) => m,
            Err(e) => { send(Event::Info { message: format!("snapshot unavailable: {e}") }).await; BTreeMap::new() }
        };
        send(Event::Snapshot { services: before }).await;
        let job_id = format!("{}-{}", std::process::id(), state.next_job());
        let result = async {
            let job = Job::create(&state.work, &job_id)?;
            let n = job.write_bundle(&files)?;
            send(Event::Info { message: format!("bundle materialized: {n} files in tmpfs") }).await;
            let code = job.run_deploy(&stack, &args, &tx).await?;
            job.shred();
            Ok::<i32, anyhow::Error>(code)
        }
        .await;
        match result {
            Ok(0) => {
                state.audit_str(&operator_email, &operator_user, "deploy", "deployed", &stack);
                send(Event::Result { status: "deployed".into(), code: 0, message: String::new() }).await;
            }
            Ok(code) => {
                state.audit_str(&operator_email, &operator_user, "deploy", "failed", &format!("{stack} exit {code}"));
                send(Event::Result { status: "failed".into(), code, message: format!("deploy.sh exited with {code}") }).await;
            }
            Err(e) => {
                state.audit_str(&operator_email, &operator_user, "deploy", "error", &e.to_string());
                send(Event::Result { status: "error".into(), code: -1, message: e.to_string() }).await;
            }
        }
    });
    let stream = ReceiverStream::new(rx).map(|e| {
        let mut line = serde_json::to_vec(&e).unwrap_or_default();
        line.push(b'\n');
        Ok::<_, std::convert::Infallible>(bytes::Bytes::from(line))
    });
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/x-ndjson")
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::from_stream(stream))
        .unwrap()
}

use futures::StreamExt;

// keep `bail` used on all targets
#[allow(dead_code)]
fn _unused() -> Result<()> { bail!("unused") }
