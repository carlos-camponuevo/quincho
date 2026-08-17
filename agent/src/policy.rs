//! `.quincho.yml` — the repository's own governance file (encrypted like every
//! other `.yml`, so it arrives inside the decrypted bundle):
//!
//! ```yaml
//! host: AZCRNRONEVTA01
//! deployers: { carlos: carlos@ipremios.com }   # linux user -> SSO email
//! builders:  { carlos: carlos@ipremios.com }
//! approvers: []
//! notify: { deploy: [..], build: [..], security: [..] }
//! ```

use anyhow::{Result, bail};
use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Debug, Deserialize, Default, Clone)]
pub struct Policy {
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub deployers: BTreeMap<String, String>,
    #[serde(default)]
    pub builders: BTreeMap<String, String>,
    #[serde(default)]
    pub approvers: Vec<String>,
    #[serde(default)]
    pub notify: Notify,
}

#[derive(Debug, Deserialize, Default, Clone)]
pub struct Notify {
    #[serde(default)]
    pub deploy: Vec<String>,
    #[serde(default)]
    pub build: Vec<String>,
    #[serde(default)]
    pub security: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Deploy,
    Build,
}

impl Policy {
    pub fn parse(yaml: &[u8]) -> Result<Self> {
        Ok(serde_yaml::from_slice(yaml)?)
    }

    /// The three facts that must agree: this machine, the linux user, the SSO email.
    /// Returns Ok(()) or the reason for refusal (never reveals which factor was wrong
    /// beyond what the operator needs to fix it).
    pub fn authorize(&self, action: Action, this_host: &str, linux_user: &str, sso_email: &str) -> Result<()> {
        if !self.host.is_empty() && !self.host.eq_ignore_ascii_case(this_host) {
            bail!("policy: repository is bound to host '{}', this is '{}'", self.host, this_host);
        }
        let list = match action {
            Action::Deploy => &self.deployers,
            Action::Build => &self.builders,
        };
        match list.get(linux_user) {
            None => bail!("policy: linux user '{linux_user}' is not listed as a {}", action.noun()),
            Some(email) if !email.eq_ignore_ascii_case(sso_email) => {
                bail!("policy: linux user '{linux_user}' is bound to another identity")
            }
            Some(_) => Ok(()),
        }
    }
}

impl Action {
    pub fn noun(self) -> &'static str {
        match self {
            Action::Deploy => "deployer",
            Action::Build => "builder",
        }
    }
}

/// Hefesto's host gate: `devops-<hostname>` may only be deployed on `<hostname>`.
pub fn host_gate(repo: &str, this_host: &str) -> Result<()> {
    let name = repo.trim_end_matches(".git").rsplit('/').next().unwrap_or(repo);
    if let Some(h) = name.strip_prefix("devops-") {
        if !h.eq_ignore_ascii_case(this_host) {
            bail!("host gate: '{name}' deploys only on '{h}', this machine is '{this_host}'");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pol() -> Policy {
        Policy::parse(b"host: EVTA01\ndeployers: { carlos: carlos@ipremios.com }\nbuilders: {}\n").unwrap()
    }

    #[test]
    fn allows_the_bound_person_on_the_bound_host() {
        assert!(pol().authorize(Action::Deploy, "evta01", "carlos", "Carlos@iPremios.com").is_ok());
    }

    #[test]
    fn refuses_other_host_user_or_email() {
        assert!(pol().authorize(Action::Deploy, "evla03", "carlos", "carlos@ipremios.com").is_err());
        assert!(pol().authorize(Action::Deploy, "evta01", "mallory", "carlos@ipremios.com").is_err());
        assert!(pol().authorize(Action::Deploy, "evta01", "carlos", "mallory@x.com").is_err());
        assert!(pol().authorize(Action::Build, "evta01", "carlos", "carlos@ipremios.com").is_err());
    }

    #[test]
    fn host_gate_binds_devops_repos_only() {
        assert!(host_gate("https://github.com/x/devops-azcrnronevta01.git", "AZCRNRONEVTA01").is_ok());
        assert!(host_gate("devops-azcrnronevta01", "azcrnronevla03").is_err());
        assert!(host_gate("https://github.com/x/some-app", "anything").is_ok());
    }
}
