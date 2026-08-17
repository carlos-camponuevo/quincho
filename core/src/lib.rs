//! quincho-core — the engine (from hefesto-core) shared by the agent and the tools:
//! configuration, in-memory vault (SOPS/age), repo download, build, deploy, runbook
//! and report/mail rendering. Nothing here is interactive except
//! `Config::load`, which prompts only when the config file itself is
//! encrypted.

pub mod apply;
pub mod brand;
pub mod build;
pub mod config;
pub mod deploy;
pub mod inventory;
pub mod mail;
pub mod manifest;
pub mod remote;
pub mod report;
pub mod runbook;
pub mod sops;
pub mod vault;
