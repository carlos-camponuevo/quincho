//! Linux credentials at the button: PAM authentication of `user`/`password`
//! (service `quincho`, see install/pam.d/quincho) plus membership of the
//! `quincho` group. The password is borrowed for the call and zeroized by the
//! caller; nothing is logged.

use anyhow::{Context, Result, bail};
use zeroize::Zeroizing;

/// Authenticate against PAM. On non-Linux builds (developer laptops) this is a
/// stub that only accepts `QUINCHO_DEV_PASSWORD` for any user, so the API can be
/// exercised locally; it is compiled out on Linux.
pub fn pam_authenticate(user: &str, password: &Zeroizing<String>) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        use pam_client::{Context as PamContext, Flag, conv_mock::Conversation};
        let conv = Conversation::with_credentials(user, password.as_str());
        let mut ctx = PamContext::new("quincho", Some(user), conv).context("PAM init")?;
        ctx.authenticate(Flag::NONE).map_err(|_| anyhow::anyhow!("authentication failed"))?;
        ctx.acct_mgmt(Flag::NONE).map_err(|_| anyhow::anyhow!("account not permitted"))?;
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let dev = std::env::var("QUINCHO_DEV_PASSWORD").unwrap_or_default();
        if !dev.is_empty() && password.as_str() == dev {
            Ok(())
        } else {
            let _ = user;
            bail!("authentication failed (non-Linux build: set QUINCHO_DEV_PASSWORD for local tests)")
        }
    }
}

/// `user` must belong to `group` (NSS-aware: `id -Gn` sees LDAP/SSSD groups too).
pub async fn in_group(user: &str, group: &str) -> Result<()> {
    if user.is_empty() || !user.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.') {
        bail!("invalid user name");
    }
    let out = tokio::process::Command::new("id").arg("-Gn").arg(user).output().await.context("running id")?;
    if !out.status.success() {
        bail!("unknown linux user '{user}'");
    }
    let groups = String::from_utf8_lossy(&out.stdout);
    if groups.split_whitespace().any(|g| g == group) {
        Ok(())
    } else {
        bail!("linux user '{user}' is not in group '{group}'")
    }
}
