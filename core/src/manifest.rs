//! The deploy-request manifest and its result — the JSON contract between
//! the request/approval flow (or an operator's file) and the deploy engine.
//! Versioned and additive: bump `SCHEMA_VERSION` only on breaking changes.
//!
//! A manifest lists stacks/services to deploy with images pinned to exact
//! references; the result records, per item, the image every service ran
//! BEFORE the deploy — which is precisely what a rollback needs.

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeployManifest {
    pub schema_version: u32,
    /// Request id from the approval flow; carried into the result and mails.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// Deployed strictly in order; a failure stops the run (after the
    /// failed item's own rollback) and marks the rest as skipped.
    pub items: Vec<ManifestItem>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ManifestItem {
    /// Stack directory in the repo ("zauat/admin", root-level "system").
    pub dir: String,
    /// None = the whole stack.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub services: Option<Vec<String>>,
    /// Pins by image basename -> full reference ("ghcr.io/ns/app@sha256:…").
    /// Every service of the stack running that image gets the reference —
    /// the natural shape for freshly built images.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub pins: BTreeMap<String, String>,
    /// Pins by service name -> full reference; wins over `pins`. This is
    /// the shape rollback uses (each service returns to ITS previous image).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub service_pins: BTreeMap<String, String>,
}

impl DeployManifest {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let m: DeployManifest =
            serde_json::from_slice(bytes).context("manifest is not valid JSON")?;
        ensure!(
            m.schema_version == SCHEMA_VERSION,
            "manifest schemaVersion {} is not supported (this binary speaks {})",
            m.schema_version,
            SCHEMA_VERSION
        );
        ensure!(!m.items.is_empty(), "manifest has no items");
        for it in &m.items {
            ensure!(!it.dir.is_empty(), "manifest item without a dir");
            if let Some(svcs) = &it.services {
                ensure!(!svcs.is_empty(), "item '{}' has an empty services list", it.dir);
            }
        }
        Ok(m)
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApplyResult {
    pub schema_version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// "apply" or "rollback".
    pub action: String,
    /// True only when every item deployed.
    pub ok: bool,
    pub items: Vec<ItemResult>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ItemResult {
    pub dir: String,
    pub stack_name: String,
    /// The services this item touched (resolved: whole stack is expanded).
    pub services: Vec<String>,
    pub status: ItemStatus,
    pub duration_secs: u64,
    /// Image each service ran before this deploy; None = the service did
    /// not exist (a first deploy — nothing to roll back to).
    pub previous: Vec<PreviousImage>,
    pub log: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ItemStatus {
    Deployed,
    /// Deploy failed and no rollback was possible (nothing recorded).
    Failed,
    /// Deploy failed; the previous images were redeployed successfully.
    RolledBack,
    /// Deploy failed AND the rollback failed — needs a human.
    RollbackFailed,
    /// Not attempted because an earlier item failed.
    Skipped,
}

impl ItemStatus {
    /// Human word for mail subjects and summaries.
    pub fn word(self) -> &'static str {
        match self {
            ItemStatus::Deployed => "deployed",
            ItemStatus::Failed => "failed",
            ItemStatus::RolledBack => "rolled back",
            ItemStatus::RollbackFailed => "ROLLBACK FAILED",
            ItemStatus::Skipped => "skipped",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreviousImage {
    pub service: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
}

impl ApplyResult {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let r: ApplyResult =
            serde_json::from_slice(bytes).context("result file is not valid JSON")?;
        ensure!(
            r.schema_version == SCHEMA_VERSION,
            "result schemaVersion {} is not supported (this binary speaks {})",
            r.schema_version,
            SCHEMA_VERSION
        );
        Ok(r)
    }

    /// Turn a result into the manifest that undoes it: every service goes
    /// back to its recorded previous image. Services that had no previous
    /// image (first deploys) are left out — reported in `skipped` so the
    /// caller can say so instead of silently shrinking the plan.
    /// Items that never deployed (skipped) are dropped.
    pub fn rollback_manifest(&self) -> (DeployManifest, Vec<String>) {
        let mut skipped: Vec<String> = Vec::new();
        let mut items: Vec<ManifestItem> = Vec::new();
        for item in &self.items {
            if item.status == ItemStatus::Skipped {
                continue;
            }
            let mut service_pins = BTreeMap::new();
            for prev in &item.previous {
                match &prev.image {
                    Some(image) => {
                        service_pins.insert(prev.service.clone(), image.clone());
                    }
                    None => skipped.push(format!("{}/{}", item.dir, prev.service)),
                }
            }
            if service_pins.is_empty() {
                continue;
            }
            items.push(ManifestItem {
                dir: item.dir.clone(),
                services: Some(service_pins.keys().cloned().collect()),
                pins: BTreeMap::new(),
                service_pins,
            });
        }
        (
            DeployManifest {
                schema_version: SCHEMA_VERSION,
                request_id: self.request_id.clone(),
                items,
            },
            skipped,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_validates() {
        let json = br#"{
            "schemaVersion": 1,
            "requestId": "req-20260805-0001",
            "items": [
                { "dir": "zauat/admin",
                  "services": ["web", "worker"],
                  "pins": { "admin-portal": "ghcr.io/my-org/admin-portal@sha256:abc" } },
                { "dir": "system" }
            ]
        }"#;
        let m = DeployManifest::parse(json).unwrap();
        assert_eq!(m.request_id.as_deref(), Some("req-20260805-0001"));
        assert_eq!(m.items.len(), 2);
        assert_eq!(m.items[0].pins["admin-portal"], "ghcr.io/my-org/admin-portal@sha256:abc");
        assert!(m.items[1].services.is_none(), "no services = whole stack");

        assert!(DeployManifest::parse(br#"{"schemaVersion": 2, "items": [{"dir":"x"}]}"#).is_err());
        assert!(DeployManifest::parse(br#"{"schemaVersion": 1, "items": []}"#).is_err());
        assert!(
            DeployManifest::parse(br#"{"schemaVersion":1,"items":[{"dir":"x","services":[]}]}"#)
                .is_err()
        );
    }

    #[test]
    fn result_round_trips_and_builds_rollback() {
        let result = ApplyResult {
            schema_version: SCHEMA_VERSION,
            request_id: Some("req-1".into()),
            action: "apply".into(),
            ok: false,
            items: vec![
                ItemResult {
                    dir: "zauat/admin".into(),
                    stack_name: "zauat-admin".into(),
                    services: vec!["web".into(), "fresh".into()],
                    status: ItemStatus::Deployed,
                    duration_secs: 12,
                    previous: vec![
                        PreviousImage {
                            service: "web".into(),
                            image: Some("ns/app@sha256:old".into()),
                        },
                        PreviousImage { service: "fresh".into(), image: None },
                    ],
                    log: String::new(),
                },
                ItemResult {
                    dir: "zauat/pix".into(),
                    stack_name: "zauat-pix".into(),
                    services: vec!["api".into()],
                    status: ItemStatus::Skipped,
                    duration_secs: 0,
                    previous: Vec::new(),
                    log: String::new(),
                },
            ],
        };
        let json = serde_json::to_vec_pretty(&result).unwrap();
        let back = ApplyResult::parse(&json).unwrap();
        assert_eq!(back.items[0].status, ItemStatus::Deployed);

        let (rb, skipped) = back.rollback_manifest();
        assert_eq!(rb.items.len(), 1, "skipped items are dropped from the rollback");
        let item = &rb.items[0];
        assert_eq!(item.dir, "zauat/admin");
        assert_eq!(item.services.as_deref(), Some(&["web".to_string()][..]));
        assert_eq!(item.service_pins["web"], "ns/app@sha256:old");
        assert_eq!(skipped, ["zauat/admin/fresh"], "first-deploy services are reported");
    }
}
