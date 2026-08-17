//! Brand assets are provided at runtime by the deployment (customer files never
//! live in this repository). Set once at start-up from a file (e.g. BullDock's
//! `/brand/logo.png`); when nothing is set, reports and runbooks render without a logo.

use std::sync::OnceLock;

static LOGO: OnceLock<Vec<u8>> = OnceLock::new();

/// Register the logo bytes (PNG). Only the first call wins.
pub fn set_logo(png: Vec<u8>) {
    let _ = LOGO.set(png);
}

/// Load the logo from a file if it exists; silently no-op otherwise.
pub fn set_logo_from_file(path: &str) {
    if let Ok(b) = std::fs::read(path) {
        if !b.is_empty() {
            set_logo(b);
        }
    }
}

pub fn logo() -> Option<&'static [u8]> {
    LOGO.get().map(|v| v.as_slice())
}
