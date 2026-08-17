//! Machine-readable inventory: every stack, service and image of the
//! repository with its build provenance, as versioned JSON. This is the
//! snapshot the web request/approval flow consumes — the schema is a
//! contract, additive changes only (bump `SCHEMA_VERSION` on breaking ones).

use crate::build::{self, BuildFile, BuildSpec};
use crate::config::Config;
use crate::vault::MemFs;
use serde::{Deserialize, Serialize};

pub const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Inventory {
    pub schema_version: u32,
    /// devops repository the snapshot came from
    pub repository: String,
    pub branch: String,
    /// host the repo is bound to ("devops-<host>"), when the name matches
    pub expected_host: Option<String>,
    pub stacks: Vec<Stack>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Stack {
    /// repo directory ("zauat/admin", or a root-level stack like "system")
    pub dir: String,
    /// environment folder; None for a root-level stack
    pub environment: Option<String>,
    /// swarm stack name (dir with '/' replaced by '-')
    pub stack_name: String,
    pub has_stack_md: bool,
    pub services: Vec<Service>,
    /// build units: services grouped by image basename, compose order
    pub images: Vec<Image>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Service {
    pub name: String,
    /// compose `image:` reference as written
    pub image: String,
    /// grouping key — basename without registry/namespace/tag
    pub image_base: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Image {
    pub base: String,
    /// services of this stack running the image (empty for build-only entries)
    pub services: Vec<String>,
    /// a build entry exists (even a disabled one — see `build.enabled`)
    pub buildable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build: Option<BuildInfo>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BuildInfo {
    pub name: String,
    pub enabled: bool,
    pub tag: String,
    pub push: bool,
    /// destination name from build.yml and the reference a build would push
    pub destination: String,
    pub image_ref: String,
    pub platform: String,
    /// "provider:org[/project]/repo @ branch"
    pub source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mail_group: Option<String>,
}

/// Walk the decrypted repo exactly like the interactive menus do:
/// root folders with their own compose are stacks, the rest are
/// environments whose compose-bearing subfolders are stacks.
pub fn build_inventory(fs: &MemFs, cfg: &Config) -> Inventory {
    let mut stacks = Vec::new();
    for root in fs.subdirs("") {
        if cfg.exclude_folders.contains(&root) || root.starts_with('.') {
            continue;
        }
        if has_compose(fs, &root) {
            stacks.push(stack_entry(fs, cfg, &root, None));
            continue;
        }
        for sub in fs.subdirs(&root) {
            let dir = format!("{root}/{sub}");
            if cfg.exclude_subfolders.contains(&sub) || !has_compose(fs, &dir) {
                continue;
            }
            stacks.push(stack_entry(fs, cfg, &dir, Some(root.clone())));
        }
    }
    Inventory {
        schema_version: SCHEMA_VERSION,
        repository: cfg.repo.repository.clone(),
        branch: cfg.repo.branch.clone(),
        expected_host: cfg.expected_hostname(),
        stacks,
    }
}

fn has_compose(fs: &MemFs, dir: &str) -> bool {
    fs.get(&format!("{dir}/docker-compose.yml")).is_some()
}

fn stack_entry(fs: &MemFs, cfg: &Config, dir: &str, environment: Option<String>) -> Stack {
    let services = compose_services(fs, dir);
    let bf = build::load(fs, dir).ok().flatten();
    let images = image_groups(cfg, &services, bf.as_ref());
    Stack {
        dir: dir.to_string(),
        environment,
        stack_name: dir.replace('/', "-"),
        has_stack_md: fs.get(&format!("{dir}/stack.md")).is_some(),
        services,
        images,
    }
}

/// Services of a stack's compose, in file order. Shared with the apply
/// engine, which needs the same name/image-base view to expand pins.
pub(crate) fn compose_services(fs: &MemFs, dir: &str) -> Vec<Service> {
    fs.get(&format!("{dir}/docker-compose.yml"))
        .and_then(|raw| serde_yaml::from_slice::<serde_yaml::Value>(raw).ok())
        .and_then(|doc| {
            Some(
                doc.get("services")?
                    .as_mapping()?
                    .iter()
                    .filter_map(|(k, v)| {
                        let name = k.as_str()?.to_string();
                        let image = v
                            .get("image")
                            .and_then(|i| i.as_str())
                            .unwrap_or_default()
                            .to_string();
                        let image_base =
                            build::image_base(&image).unwrap_or_else(|| image.clone());
                        Some(Service { name, image, image_base })
                    })
                    .collect(),
            )
        })
        .unwrap_or_default()
}

/// Group services by image basename (compose order) and attach build
/// provenance. Mirrors the menu logic: a stack-level build list also
/// contributes entries no service uses; an environment catalog does not.
fn image_groups(cfg: &Config, services: &[Service], bf: Option<&BuildFile>) -> Vec<Image> {
    let mut groups: Vec<Image> = Vec::new();
    for svc in services {
        match groups.iter_mut().find(|g| g.base == svc.image_base) {
            Some(g) => g.services.push(svc.name.clone()),
            None => {
                let spec = bf.and_then(|bf| build::find_by_image(bf, &svc.image_base));
                groups.push(Image {
                    base: svc.image_base.clone(),
                    services: vec![svc.name.clone()],
                    buildable: spec.is_some(),
                    build: spec.and_then(|s| build_info(cfg, bf.unwrap(), s)),
                });
            }
        }
    }
    if let Some(bf) = bf.filter(|bf| !bf.catalog) {
        for spec in bf.entries() {
            if !groups.iter().any(|g| g.base == spec.image_name()) {
                groups.push(Image {
                    base: spec.image_name(),
                    services: Vec::new(),
                    buildable: true,
                    build: build_info(cfg, bf, spec),
                });
            }
        }
    }
    groups
}

fn build_info(cfg: &Config, bf: &BuildFile, spec: &BuildSpec) -> Option<BuildInfo> {
    let (dest_name, dest) = bf.destination_for(spec).ok()?;
    let source = spec
        .source_repo(cfg)
        .map(|r| {
            let project = if r.project.is_empty() {
                String::new()
            } else {
                format!("/{}", r.project)
            };
            format!("{}:{}{}/{} @ {}", r.provider, r.organization, project, r.repository, r.branch)
        })
        .unwrap_or_default();
    Some(BuildInfo {
        name: spec.display_name(),
        enabled: spec.enabled,
        tag: spec.tag.clone(),
        push: spec.push,
        destination: dest_name.to_string(),
        image_ref: dest.image_ref(&spec.image_name(), &spec.tag),
        platform: spec
            .platform
            .clone()
            .unwrap_or_else(|| bf.default_platform.clone()),
        source,
        mail_group: spec.mail_group.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn fixture() -> (MemFs, Config) {
        let mut fs = MemFs::default();
        // root-level stack
        fs.files.insert(
            "system/docker-compose.yml".into(),
            b"services:\n  traefik:\n    image: traefik:v2\n".to_vec(),
        );
        // environment with one stack: two services on one image + a stock one
        fs.files.insert(
            "zauat/admin/docker-compose.yml".into(),
            b"services:\n  web:\n    image: my-user/admin-portal:uat.latest\n  worker:\n    image: my-user/admin-portal:uat.latest\n  cache:\n    image: redis:7\n".to_vec(),
        );
        fs.files.insert("zauat/admin/stack.md".into(), b"# admin\n".to_vec());
        fs.files.insert(
            "zauat/admin/build.yml".into(),
            b"destinations:\n  hub: { host: docker.io, namespace: my-user }\nrepoList:\n  - repoUrl: https://dev.azure.com/ExampleOrg/App/_git/admin-portal-src\n    image: admin-portal\n    branch: release/uat\n    tag: uat.latest\n  - repoUrl: https://dev.azure.com/ExampleOrg/App/_git/extra-tool\n    tag: uat.latest\n    enabled: false\n".to_vec(),
        );
        // excluded folder and excluded subfolder must not appear
        fs.files.insert(
            "shared/whatever/docker-compose.yml".into(),
            b"services: {}\n".to_vec(),
        );
        fs.files.insert(
            "zauat/conf/docker-compose.yml".into(),
            b"services: {}\n".to_vec(),
        );
        let cfg =
            Config::from_git_url("https://dev.azure.com/ExampleOrg/Devops/_git/devops-server01")
                .unwrap();
        (fs, cfg)
    }

    #[test]
    fn walks_stacks_and_groups_images() {
        let (fs, cfg) = fixture();
        let inv = build_inventory(&fs, &cfg);
        assert_eq!(inv.schema_version, SCHEMA_VERSION);
        assert_eq!(inv.expected_host.as_deref(), Some("server01"));

        let dirs: Vec<&str> = inv.stacks.iter().map(|s| s.dir.as_str()).collect();
        assert_eq!(dirs, ["system", "zauat/admin"], "excluded folders must not appear");

        let sys = &inv.stacks[0];
        assert_eq!(sys.environment, None);
        assert_eq!(sys.stack_name, "system");

        let admin = &inv.stacks[1];
        assert_eq!(admin.environment.as_deref(), Some("zauat"));
        assert_eq!(admin.stack_name, "zauat-admin");
        assert!(admin.has_stack_md);
        assert_eq!(admin.services.len(), 3);

        // two services share one image; redis is a stock image
        let portal = admin.images.iter().find(|i| i.base == "admin-portal").unwrap();
        assert_eq!(portal.services, ["web", "worker"]);
        assert!(portal.buildable);
        let info = portal.build.as_ref().unwrap();
        assert!(info.enabled);
        assert_eq!(info.image_ref, "my-user/admin-portal:uat.latest");
        assert_eq!(info.platform, "linux/amd64");
        assert_eq!(info.source, "azdo:ExampleOrg/App/admin-portal-src @ release/uat");

        let redis = admin.images.iter().find(|i| i.base == "redis").unwrap();
        assert!(!redis.buildable);
        assert!(redis.build.is_none());

        // build-only entry appears with no services, disabled documented
        let extra = admin.images.iter().find(|i| i.base == "extra-tool").unwrap();
        assert!(extra.services.is_empty());
        assert!(!extra.build.as_ref().unwrap().enabled);
    }

    #[test]
    fn round_trips_as_json() {
        let (fs, cfg) = fixture();
        let inv = build_inventory(&fs, &cfg);
        let json = serde_json::to_string_pretty(&inv).unwrap();
        assert!(json.contains("\"schemaVersion\": 1"), "camelCase keys expected:\n{json}");
        assert!(json.contains("\"imageBase\": \"admin-portal\""));
        let back: Inventory = serde_json::from_str(&json).unwrap();
        assert_eq!(back.stacks.len(), inv.stacks.len());
    }
}
