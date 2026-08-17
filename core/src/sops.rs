//! SOPS + age vault: decrypt files that `ed.sh` 2.x stores whole as `<name>.sops`
//! (SOPS "binary" mode, age recipients). Everything happens in memory; the age
//! identity is borrowed for the call and never stored by this module.
//!
//! File shape (JSON):
//! ```json
//! { "data": "ENC[AES256_GCM,data:…,iv:…,tag:…,type:str]",
//!   "sops": { "age": [ { "recipient": "age1…", "enc": "-----BEGIN AGE ENCRYPTED FILE-----…" } ],
//!             "mac": "ENC[…]", "version": "3.x", … } }
//! ```
//! The 32-byte data key is age-encrypted per recipient; the payload is AES-256-GCM
//! with a 32-byte IV and the tree path (`"data:"`) as additional data — exactly
//! what SOPS does, so files written by SOPS decrypt here and vice versa.

use aes_gcm::{
    AesGcm, Key,
    aead::{Aead, KeyInit, Payload},
};
use anyhow::{Context, Result, anyhow, bail, ensure};
use base64::Engine;
use serde::Deserialize;
use std::io::Read;
use typenum::U32;
use zeroize::Zeroizing;

/// AES-256-GCM with SOPS' 32-byte nonce.
type SopsGcm = AesGcm<aes_gcm::aes::Aes256, U32>;

#[derive(Deserialize)]
struct SopsFile {
    data: String,
    sops: SopsMeta,
}

#[derive(Deserialize)]
struct SopsMeta {
    #[serde(default)]
    age: Vec<AgeEntry>,
    #[serde(default)]
    version: String,
}

#[derive(Deserialize)]
struct AgeEntry {
    recipient: String,
    enc: String,
}

/// An age identity (`AGE-SECRET-KEY-1…`), zeroized on drop.
pub struct Identity {
    inner: age::x25519::Identity,
    public: String,
}

impl Identity {
    /// Parse a Bech32 secret key. The input string is zeroized after parsing.
    pub fn parse(secret: Zeroizing<String>) -> Result<Self> {
        let inner: age::x25519::Identity = secret
            .trim()
            .parse()
            .map_err(|e: &str| anyhow!("not an age secret key: {e}"))?;
        let public = inner.to_public().to_string();
        Ok(Self { inner, public })
    }

    /// Read `~/.config/sops/age/keys.txt`-style content: first `AGE-SECRET-KEY-1…` line wins.
    pub fn from_keys_file(content: Zeroizing<String>) -> Result<Self> {
        for line in content.lines() {
            let l = line.trim();
            if l.starts_with("AGE-SECRET-KEY-1") {
                return Self::parse(Zeroizing::new(l.to_string()));
            }
        }
        bail!("no AGE-SECRET-KEY-1… line found")
    }

    pub fn public_key(&self) -> &str {
        &self.public
    }
}

/// True when the bytes look like a SOPS envelope (JSON with a top-level "sops" object).
pub fn looks_sops(data: &[u8]) -> bool {
    let head = &data[..data.len().min(4096)];
    let Ok(s) = std::str::from_utf8(head) else { return false };
    let t = s.trim_start();
    t.starts_with('{') && (t.contains("\"sops\"") || s.contains("\"sops\""))
}

/// Recipients (age public keys) a SOPS file is encrypted for — readable without any key.
pub fn recipients(data: &[u8]) -> Result<Vec<String>> {
    let f: SopsFile = serde_json::from_slice(data).context("not a SOPS JSON envelope")?;
    Ok(f.sops.age.into_iter().map(|a| a.recipient).collect())
}

/// Decrypt one SOPS binary-mode file with the given identity.
pub fn decrypt(data: &[u8], id: &Identity) -> Result<Zeroizing<Vec<u8>>> {
    let f: SopsFile = serde_json::from_slice(data).context("not a SOPS JSON envelope")?;
    ensure!(!f.sops.age.is_empty(), "SOPS file has no age recipients (kms/pgp-only files are not supported)");
    // 1) unwrap the data key with our identity (try the matching recipient first, then all)
    let mut key: Option<Zeroizing<Vec<u8>>> = None;
    let mut ordered: Vec<&AgeEntry> = f.sops.age.iter().filter(|a| a.recipient == id.public).collect();
    ordered.extend(f.sops.age.iter().filter(|a| a.recipient != id.public));
    let mut last_err = None;
    for entry in ordered {
        match age_decrypt_armored(&entry.enc, &id.inner) {
            Ok(k) => { key = Some(k); break; }
            Err(e) => last_err = Some(e),
        }
    }
    let key = key.ok_or_else(|| {
        anyhow!(
            "this identity ({}) cannot open the file (recipients: {}){}",
            id.public,
            f.sops.age.iter().map(|a| a.recipient.as_str()).collect::<Vec<_>>().join(", "),
            last_err.map(|e| format!(": {e}")).unwrap_or_default()
        )
    })?;
    ensure!(key.len() == 32, "unwrapped data key has {} bytes, expected 32", key.len());
    // 2) decrypt the payload
    let plain = decrypt_value(&f.data, &key, "data:")
        .with_context(|| format!("decrypting payload (SOPS {})", f.sops.version))?;
    Ok(plain)
}

fn age_decrypt_armored(armored: &str, id: &age::x25519::Identity) -> Result<Zeroizing<Vec<u8>>> {
    let reader = age::armor::ArmoredReader::new(armored.as_bytes());
    let decryptor = age::Decryptor::new(reader).map_err(|e| anyhow!("age header: {e}"))?;
    let mut out = Zeroizing::new(Vec::with_capacity(64));
    let mut r = decryptor
        .decrypt(std::iter::once(id as &dyn age::Identity))
        .map_err(|e| anyhow!("age decrypt: {e}"))?;
    r.read_to_end(&mut out)?;
    Ok(out)
}

/// Parse `ENC[AES256_GCM,data:…,iv:…,tag:…,type:…]` and decrypt with `aad` as additional data.
fn decrypt_value(enc: &str, key: &[u8], aad: &str) -> Result<Zeroizing<Vec<u8>>> {
    let inner = enc
        .strip_prefix("ENC[AES256_GCM,")
        .and_then(|s| s.strip_suffix(']'))
        .ok_or_else(|| anyhow!("value is not ENC[AES256_GCM,…]"))?;
    let (mut data, mut iv, mut tag) = (None, None, None);
    for part in inner.split(',') {
        if let Some(v) = part.strip_prefix("data:") { data = Some(v) }
        else if let Some(v) = part.strip_prefix("iv:") { iv = Some(v) }
        else if let Some(v) = part.strip_prefix("tag:") { tag = Some(v) }
    }
    let b64 = base64::engine::general_purpose::STANDARD;
    let mut ct = b64.decode(data.ok_or_else(|| anyhow!("missing data:"))?)?;
    let iv = b64.decode(iv.ok_or_else(|| anyhow!("missing iv:"))?)?;
    let tag = b64.decode(tag.ok_or_else(|| anyhow!("missing tag:"))?)?;
    ensure!(iv.len() == 32, "SOPS IV must be 32 bytes, got {}", iv.len());
    ensure!(tag.len() == 16, "GCM tag must be 16 bytes, got {}", tag.len());
    ct.extend_from_slice(&tag); // aes-gcm expects ciphertext || tag
    let cipher = SopsGcm::new(Key::<SopsGcm>::from_slice(key));
    let nonce = aes_gcm::Nonce::<U32>::from_slice(&iv);
    let plain = cipher
        .decrypt(nonce, Payload { msg: &ct, aad: aad.as_bytes() })
        .map_err(|_| anyhow!("AES-GCM authentication failed (wrong key or tampered file)"))?;
    Ok(Zeroizing::new(plain))
}

impl crate::vault::MemFs {
    /// Decrypt every `*.sops` entry in place with the identity: `x.yml.sops` becomes
    /// `x.yml`. Fails on the first file the identity cannot open, leaving the vault
    /// intact. Returns the number of files decrypted.
    pub fn decrypt_sops(&mut self, id: &Identity) -> Result<usize> {
        let paths: Vec<String> = self.files.keys().filter(|k| k.ends_with(".sops")).cloned().collect();
        let mut n = 0;
        for path in &paths {
            let data = self.files.get(path).unwrap();
            let plain = decrypt(data, id).with_context(|| format!("decrypting '{path}'"))?;
            let target = path.trim_end_matches(".sops").to_string();
            self.files.remove(path);
            self.files.insert(target, plain.to_vec());
            n += 1;
        }
        Ok(n)
    }

    /// Age recipients used across the repository (union), without decrypting anything.
    pub fn sops_recipients(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .files
            .iter()
            .filter(|(k, _)| k.ends_with(".sops"))
            .filter_map(|(_, v)| recipients(v).ok())
            .flatten()
            .collect();
        out.sort();
        out.dedup();
        out
    }
}
