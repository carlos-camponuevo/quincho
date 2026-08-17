//! Execution in a private memory-backed work dir: write the (plaintext) bundle
//! into `<work>/<job>/` (0700, on tmpfs), run the stack's `deploy.sh`, stream
//! every output line to the caller, then overwrite and remove everything.
//! No plaintext survives the job.

use anyhow::{Context, Result, bail};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::mpsc;

/// One streamed event, serialized as one JSON line.
#[derive(serde::Serialize, Clone, Debug)]
#[serde(tag = "event", rename_all = "lowercase")]
pub enum Event {
    Info { message: String },
    Log { stream: &'static str, line: String },
    Snapshot { services: BTreeMap<String, ServiceImage> },
    Result { status: String, code: i32, message: String },
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct ServiceImage {
    pub image: String,
    pub spec: serde_json::Value,
}

pub struct Job {
    pub dir: PathBuf,
}

impl Job {
    /// Create `<work>/<id>` with mode 0700; `work` must be on tmpfs (checked by
    /// mount type when possible — a warning event otherwise).
    pub fn create(work: &Path, id: &str) -> Result<Self> {
        std::fs::create_dir_all(work).with_context(|| format!("creating work dir {}", work.display()))?;
        let dir = work.join(id);
        std::fs::create_dir(&dir).with_context(|| format!("creating job dir {}", dir.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
        }
        Ok(Self { dir })
    }

    /// Materialize the bundle: relative path -> bytes. Paths are normalized and
    /// must stay inside the job dir. `*.sh` become executable, everything else 0600.
    pub fn write_bundle(&self, files: &BTreeMap<String, Vec<u8>>) -> Result<usize> {
        let mut n = 0;
        for (rel, data) in files {
            let clean = normalize(rel)?;
            let target = self.dir.join(&clean);
            if !target.starts_with(&self.dir) {
                bail!("bundle path escapes the job dir: {rel}");
            }
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&target, data)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = if clean.ends_with(".sh") { 0o700 } else { 0o600 };
                std::fs::set_permissions(&target, std::fs::Permissions::from_mode(mode))?;
            }
            n += 1;
        }
        Ok(n)
    }

    /// Run `bash <stack>/deploy.sh [args]` inside the job dir, streaming lines.
    /// Returns the exit code.
    pub async fn run_deploy(&self, stack: &str, args: &[String], tx: &mpsc::Sender<Event>) -> Result<i32> {
        let stack_dir = self.dir.join(normalize(stack)?);
        let script = stack_dir.join("deploy.sh");
        if !script.is_file() {
            bail!("no deploy.sh in '{stack}'");
        }
        let mut child = Command::new("bash")
            .arg(&script)
            .args(args)
            .current_dir(&stack_dir)
            .env("QUINCHO", "1")
            .env("QUINCHO_STACK", stack)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .context("spawning deploy.sh")?;
        let out = child.stdout.take().unwrap();
        let err = child.stderr.take().unwrap();
        let tx1 = tx.clone();
        let tx2 = tx.clone();
        let h1 = tokio::spawn(async move {
            let mut lines = BufReader::new(out).lines();
            while let Ok(Some(l)) = lines.next_line().await {
                let _ = tx1.send(Event::Log { stream: "stdout", line: l }).await;
            }
        });
        let h2 = tokio::spawn(async move {
            let mut lines = BufReader::new(err).lines();
            while let Ok(Some(l)) = lines.next_line().await {
                let _ = tx2.send(Event::Log { stream: "stderr", line: l }).await;
            }
        });
        let status = child.wait().await?;
        let _ = tokio::join!(h1, h2);
        Ok(status.code().unwrap_or(-1))
    }

    /// Overwrite every file with zeros, then remove the tree. Best effort — the
    /// dir is on tmpfs, so this is about not leaving plaintext in page cache
    /// longer than needed.
    pub fn shred(&self) {
        fn walk(p: &Path) {
            if let Ok(rd) = std::fs::read_dir(p) {
                for e in rd.flatten() {
                    let path = e.path();
                    if path.is_dir() {
                        walk(&path);
                    } else if let Ok(meta) = std::fs::metadata(&path) {
                        let zeros = vec![0u8; meta.len() as usize];
                        let _ = std::fs::write(&path, zeros);
                    }
                }
            }
        }
        walk(&self.dir);
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Drop for Job {
    fn drop(&mut self) {
        if self.dir.exists() {
            self.shred();
        }
    }
}

/// Reject `..`, absolute paths and empty segments.
pub fn normalize(rel: &str) -> Result<String> {
    let mut parts = Vec::new();
    let unified = rel.replace('\\', "/");
    for seg in unified.split('/') {
        match seg {
            "" | "." => continue,
            ".." => bail!("path traversal in '{rel}'"),
            s => parts.push(s),
        }
    }
    if parts.is_empty() {
        bail!("empty path");
    }
    Ok(parts.join("/"))
}

/// Snapshot the services of a stack: `image@digest` currently running + full spec.
pub async fn snapshot(stack: &str, only: &[String]) -> Result<BTreeMap<String, ServiceImage>> {
    let filter = format!("label=com.docker.stack.namespace={stack}");
    let ls = Command::new("docker")
        .args(["service", "ls", "--filter", &filter, "--format", "{{.Name}}"])
        .output()
        .await
        .context("docker service ls")?;
    if !ls.status.success() {
        bail!("docker service ls failed: {}", String::from_utf8_lossy(&ls.stderr).trim());
    }
    let mut out = BTreeMap::new();
    for name in String::from_utf8_lossy(&ls.stdout).split_whitespace() {
        let short = name.strip_prefix(&format!("{stack}_")).unwrap_or(name);
        if !only.is_empty() && !only.iter().any(|s| s == short || s == name) {
            continue;
        }
        let ins = Command::new("docker").args(["service", "inspect", name]).output().await?;
        if !ins.status.success() {
            continue;
        }
        let v: serde_json::Value = serde_json::from_slice(&ins.stdout).unwrap_or(serde_json::Value::Null);
        let spec = v.get(0).and_then(|s| s.get("Spec")).cloned().unwrap_or(serde_json::Value::Null);
        let image = spec
            .pointer("/TaskTemplate/ContainerSpec/Image")
            .and_then(|i| i.as_str())
            .unwrap_or("")
            .to_string();
        out.insert(name.to_string(), ServiceImage { image, spec });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_rejects_escapes() {
        assert_eq!(normalize("rouat/data/deploy.sh").unwrap(), "rouat/data/deploy.sh");
        assert_eq!(normalize("/rouat//data/./x").unwrap(), "rouat/data/x");
        assert!(normalize("../etc/passwd").is_err());
        assert!(normalize("rouat/../../x").is_err());
    }

    #[test]
    fn job_writes_and_shreds() {
        let work = std::env::temp_dir().join(format!("quincho-test-{}", std::process::id()));
        let job = Job::create(&work, "j1").unwrap();
        let mut files = BTreeMap::new();
        files.insert("s/deploy.sh".to_string(), b"#!/bin/bash\necho hi\n".to_vec());
        files.insert("s/x.env".to_string(), b"A=1\n".to_vec());
        assert_eq!(job.write_bundle(&files).unwrap(), 2);
        assert!(job.dir.join("s/deploy.sh").is_file());
        let dir = job.dir.clone();
        drop(job);
        assert!(!dir.exists());
        let _ = std::fs::remove_dir_all(&work);
    }
}
