//! The apply engine: execute a [`DeployManifest`] item by item.
//!
//! Per item, in order: resolve the services, record the image every one of
//! them is currently running (the rollback point), deploy with the pinned
//! references, and on failed convergence redeploy the recorded images.
//! A failure stops the run — the remaining items are marked skipped, so a
//! multi-stack request is never left half-applied silently.

use crate::deploy::{self, Target};
use crate::inventory::{self, Service};
use crate::manifest::{
    ApplyResult, DeployManifest, ItemResult, ItemStatus, ManifestItem, PreviousImage,
    SCHEMA_VERSION,
};
use crate::vault::MemFs;
use std::collections::BTreeMap;

/// Run the whole manifest. `action` labels the result ("apply" or
/// "rollback") — a rollback run does NOT roll back again on failure, it
/// reports `rollback-failed` and stops.
pub fn run(fs: &MemFs, m: &DeployManifest, action: &str) -> ApplyResult {
    let auto_rollback = action != "rollback";
    let mut items: Vec<ItemResult> = Vec::new();
    let mut failed = false;
    for item in &m.items {
        if failed {
            items.push(skipped(item));
            continue;
        }
        let r = run_item(fs, item, auto_rollback);
        failed = r.status != ItemStatus::Deployed;
        items.push(r);
    }
    let ok_n = items.iter().filter(|i| i.status == ItemStatus::Deployed).count();
    eprintln!("\n🏁 {ok_n}/{} manifest items deployed", items.len());
    ApplyResult {
        schema_version: SCHEMA_VERSION,
        request_id: m.request_id.clone(),
        action: action.to_string(),
        ok: ok_n == items.len(),
        items,
    }
}

fn skipped(item: &ManifestItem) -> ItemResult {
    ItemResult {
        dir: item.dir.clone(),
        stack_name: item.dir.replace('/', "-"),
        services: item.services.clone().unwrap_or_default(),
        status: ItemStatus::Skipped,
        duration_secs: 0,
        previous: Vec::new(),
        log: "skipped: an earlier item failed".into(),
    }
}

fn run_item(fs: &MemFs, item: &ManifestItem, auto_rollback: bool) -> ItemResult {
    let started = std::time::Instant::now();
    let stack_name = item.dir.replace('/', "-");
    let fail = |log: String, started: std::time::Instant| ItemResult {
        dir: item.dir.clone(),
        stack_name: stack_name.clone(),
        services: item.services.clone().unwrap_or_default(),
        status: ItemStatus::Failed,
        duration_secs: started.elapsed().as_secs(),
        previous: Vec::new(),
        log,
    };

    let all = inventory::compose_services(fs, &item.dir);
    if all.is_empty() {
        return fail(
            format!("no services found in {}/docker-compose.yml — was the repo decrypted?", item.dir),
            started,
        );
    }
    let services = match resolve_services(item, &all) {
        Ok(s) => s,
        Err(missing) => return fail(missing, started),
    };
    let pins = expand_pins(item, &services);
    for base in item.pins.keys() {
        if !services.iter().any(|s| &s.image_base == base) {
            eprintln!("⚠️  pin '{base}' matches no service being deployed in {}", item.dir);
        }
    }

    // The rollback point: what every touched service runs RIGHT NOW.
    let previous: Vec<PreviousImage> = services
        .iter()
        .map(|s| PreviousImage {
            service: s.name.clone(),
            image: deploy::service_image(&format!("{stack_name}_{}", s.name)),
        })
        .collect();

    let names: Vec<String> = services.iter().map(|s| s.name.clone()).collect();
    let target = match &item.services {
        None => Target::WholeStack,
        Some(_) => Target::Services(names.clone()),
    };

    let done = |status: ItemStatus, log: String| ItemResult {
        dir: item.dir.clone(),
        stack_name: stack_name.clone(),
        services: names.clone(),
        status,
        duration_secs: started.elapsed().as_secs(),
        previous: previous.clone(),
        log,
    };

    match deploy::run_deploy(fs, &item.dir, target, &pins) {
        Ok(r) if r.ok => done(ItemStatus::Deployed, r.log),
        // docker ran and failed — swarm state may have moved; roll back
        Ok(r) if auto_rollback => {
            let (status, log) = roll_back(fs, item, &stack_name, &previous, r.log);
            done(status, log)
        }
        Ok(r) => done(ItemStatus::Failed, r.log),
        // preparation failed (missing env file, bad compose) — docker never
        // ran, nothing changed, nothing to roll back
        Err(e) => done(ItemStatus::Failed, format!("{e:#}")),
    }
}

/// Redeploy the recorded images of every service that has one.
fn roll_back(
    fs: &MemFs,
    item: &ManifestItem,
    stack_name: &str,
    previous: &[PreviousImage],
    mut log: String,
) -> (ItemStatus, String) {
    let rb_pins: BTreeMap<String, String> = previous
        .iter()
        .filter_map(|p| p.image.clone().map(|i| (p.service.clone(), i)))
        .collect();
    if rb_pins.is_empty() {
        log.push_str("\n(no previous images recorded — nothing to roll back to)");
        return (ItemStatus::Failed, log);
    }
    eprintln!("⏪ rolling back {stack_name} to the previously recorded images");
    let target = Target::Services(rb_pins.keys().cloned().collect());
    match deploy::run_deploy(fs, &item.dir, target, &rb_pins) {
        Ok(rb) => {
            log.push_str("\n--- rollback ---\n");
            log.push_str(&rb.log);
            if rb.ok {
                (ItemStatus::RolledBack, log)
            } else {
                (ItemStatus::RollbackFailed, log)
            }
        }
        Err(e) => {
            log.push_str(&format!("\n--- rollback ---\n{e:#}"));
            (ItemStatus::RollbackFailed, log)
        }
    }
}

/// The item's services resolved against the compose (whole stack = all),
/// or an error naming what the manifest asked for that does not exist —
/// a pinned, approved plan must not silently deploy a subset.
fn resolve_services<'a>(
    item: &ManifestItem,
    all: &'a [Service],
) -> Result<Vec<&'a Service>, String> {
    match &item.services {
        None => Ok(all.iter().collect()),
        Some(keep) => {
            let missing: Vec<&str> = keep
                .iter()
                .filter(|k| !all.iter().any(|s| &s.name == *k))
                .map(|k| k.as_str())
                .collect();
            if !missing.is_empty() {
                return Err(format!(
                    "services not in {}/docker-compose.yml: {}",
                    item.dir,
                    missing.join(", ")
                ));
            }
            Ok(all.iter().filter(|s| keep.contains(&s.name)).collect())
        }
    }
}

/// Per-service pin map: an explicit servicePin wins, else the pin of the
/// service's image basename applies. Services without either keep the
/// compose tag (resolved by the registry as today).
fn expand_pins(item: &ManifestItem, services: &[&Service]) -> BTreeMap<String, String> {
    let mut pins = BTreeMap::new();
    for svc in services {
        if let Some(r) = item.service_pins.get(&svc.name) {
            pins.insert(svc.name.clone(), r.clone());
        } else if let Some(r) = item.pins.get(&svc.image_base) {
            pins.insert(svc.name.clone(), r.clone());
        }
    }
    pins
}

#[cfg(test)]
mod tests {
    use super::*;

    fn services() -> Vec<Service> {
        let svc = |name: &str, image: &str| Service {
            name: name.into(),
            image: image.into(),
            image_base: crate::build::image_base(image).unwrap(),
        };
        vec![
            svc("web", "ns/portal:latest"),
            svc("worker", "ns/portal:latest"),
            svc("cache", "redis:7"),
        ]
    }

    fn item(services: Option<Vec<&str>>) -> ManifestItem {
        ManifestItem {
            dir: "zauat/admin".into(),
            services: services.map(|v| v.into_iter().map(String::from).collect()),
            pins: BTreeMap::from([("portal".to_string(), "ns/portal@sha256:new".to_string())]),
            service_pins: BTreeMap::from([(
                "worker".to_string(),
                "ns/portal@sha256:special".to_string(),
            )]),
        }
    }

    #[test]
    fn expands_base_pins_per_service_with_service_pin_winning() {
        let all = services();
        let item = item(None);
        let resolved = resolve_services(&item, &all).unwrap();
        let pins = expand_pins(&item, &resolved);
        assert_eq!(pins["web"], "ns/portal@sha256:new", "base pin reaches every service");
        assert_eq!(pins["worker"], "ns/portal@sha256:special", "servicePin wins over pin");
        assert!(!pins.contains_key("cache"), "unpinned stock image stays tag-based");
    }

    #[test]
    fn rejects_unknown_services() {
        let all = services();
        let err = resolve_services(&item(Some(vec!["web", "ghost"])), &all).unwrap_err();
        assert!(err.contains("ghost"), "missing service must be named: {err}");
        let ok = resolve_services(&item(Some(vec!["cache"])), &all).unwrap();
        assert_eq!(ok.len(), 1);
    }
}
