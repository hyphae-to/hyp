//! User-level harness locations used by setup, onboarding, and diagnostics.

use crate::setup::ClaudeConfigProfile;
use hyp_harness::protocol::HarnessKind;
use serde::{Deserialize, Deserializer, de};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HarnessSpec {
    #[serde(rename = "id", deserialize_with = "deserialize_harness")]
    pub kind: HarnessKind,
    pub label: String,
    setup_label: Option<String>,
    pub setup_location: String,
    pub cli: Option<String>,
    aliases: Vec<String>,
    detection: Vec<String>,
    fallback_detection: Option<FallbackDetection>,
    setup_skill_root: Option<String>,
    runtime_skill_root: String,
    legacy_skill_roots: Vec<String>,
    pub diagnostic: Option<Diagnostic>,
}

#[derive(Deserialize)]
struct FallbackDetection {
    directory: String,
    without: String,
}

#[derive(Deserialize)]
pub(crate) struct Diagnostic {
    pub path: String,
    pub test: DiagnosticTest,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DiagnosticTest {
    Exists,
    Hooks,
}

pub(crate) fn relative_path(home: &Path, relative: &str) -> PathBuf {
    relative
        .split('/')
        .fold(home.to_path_buf(), |path, part| path.join(part))
}

fn deserialize_harness<'de, D: Deserializer<'de>>(de: D) -> Result<HarnessKind, D::Error> {
    String::deserialize(de)?.parse().map_err(de::Error::custom)
}

pub(crate) fn spec(kind: HarnessKind) -> &'static HarnessSpec {
    static SPECS: OnceLock<Vec<HarnessSpec>> = OnceLock::new();
    SPECS
        .get_or_init(|| {
            serde_json::from_str(include_str!("harness_specs.json"))
                .expect("valid embedded harness specs")
        })
        .iter()
        .find(|spec| spec.kind == kind)
        .expect("spec for every HarnessKind")
}

impl HarnessSpec {
    pub fn setup_label(&self) -> &str {
        self.setup_label.as_deref().unwrap_or(&self.label)
    }

    pub fn matches_alias(&self, value: &str) -> bool {
        self.kind.as_str().eq_ignore_ascii_case(value)
            || self
                .aliases
                .iter()
                .any(|alias| alias.eq_ignore_ascii_case(value))
    }

    pub fn detected(&self, home: &Path, profiles: &[ClaudeConfigProfile]) -> bool {
        if self.kind == HarnessKind::Claude {
            return profiles
                .iter()
                .any(|profile| profile.config_dir.exists() || profile.mcp_file.exists());
        }
        self.detection
            .iter()
            .any(|relative| relative_path(home, relative).exists())
            || self.fallback_detection.as_ref().is_some_and(|fallback| {
                relative_path(home, &fallback.directory).is_dir()
                    && !relative_path(home, &fallback.without).exists()
            })
    }

    pub fn config_location(&self, home: &Path) -> PathBuf {
        relative_path(home, self.setup_location.trim_start_matches("~/"))
    }

    pub fn diagnostic_path(&self, home: &Path, diagnostic: &Diagnostic) -> PathBuf {
        let root = self.config_location(home);
        if diagnostic.path.is_empty() {
            return root;
        }
        relative_path(&root, &diagnostic.path)
    }

    pub fn setup_skill(&self, home: &Path) -> Option<PathBuf> {
        self.setup_skill_root
            .as_deref()
            .map(|root| relative_path(home, root).join("hyp-setup").join("SKILL.md"))
    }

    pub fn legacy_skills(&self, home: &Path, name: &str) -> Vec<PathBuf> {
        self.legacy_skill_roots
            .iter()
            .map(|root| relative_path(home, root).join(name).join("SKILL.md"))
            .collect()
    }

    pub fn runtime_skill(&self, home: &Path) -> PathBuf {
        relative_path(home, &self.runtime_skill_root)
            .join("hyp-mesh")
            .join("SKILL.md")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn automatic_detection_preserves_bare_gemini_fallback_and_accepts_herdr_core() {
        let home = tempfile::tempdir().unwrap();
        std::fs::create_dir(home.path().join(".gemini")).unwrap();
        std::fs::create_dir_all(home.path().join(".config/herdr-core")).unwrap();
        assert!(spec(HarnessKind::Antigravity).detected(home.path(), &[]));
        assert!(spec(HarnessKind::Herdr).detected(home.path(), &[]));
        std::fs::write(home.path().join(".gemini/settings.json"), "{}").unwrap();
        assert!(!spec(HarnessKind::Antigravity).detected(home.path(), &[]));
        std::fs::create_dir(home.path().join(".gemini/antigravity-cli")).unwrap();
        assert!(spec(HarnessKind::Antigravity).detected(home.path(), &[]));
    }
}
