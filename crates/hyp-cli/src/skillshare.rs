//! Optional Skillshare ownership. All subprocesses use the selected home, never a
//! project config; a failed manager operation never falls back to direct writes.
use crate::config_file::write_atomic_file;
use hyp_harness_ipc::protocol::HarnessKind;
use hyp_harness_transport::executable::{PathSearchPolicy, WindowsSuffixes, find_in_path};
use serde_json::{Value, json};
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

pub(crate) struct Skillshare {
    executable: PathBuf,
    home: PathBuf,
    mcp_target: Option<&'static str>,
}

impl Skillshare {
    fn current_home_matches(&self) -> bool {
        #[cfg(windows)]
        let current = std::env::var_os("USERPROFILE").or_else(|| std::env::var_os("HOME"));
        #[cfg(not(windows))]
        let current = std::env::var_os("HOME");
        current.as_deref() == Some(self.home.as_os_str())
    }
    pub(crate) fn for_claude_desktop(mut self) -> Self {
        self.mcp_target = Some("claude-desktop");
        self
    }
    fn skill_record(&self, path: &Path) -> PathBuf {
        self.home
            .join(".config/hyphae/skillshare/paths")
            .join(format!(
                "{}.json",
                hyp_store::sha256_hex(path.to_string_lossy().as_bytes())
            ))
    }
    pub(crate) fn resolve_skill_path(&self, path: &Path) -> Result<PathBuf, String> {
        if let Ok(bytes) = fs::read(self.skill_record(path)) {
            let record: Value = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
            if let Some(installed) = record["path"].as_str() {
                let installed = PathBuf::from(installed);
                if installed.is_file() {
                    return Ok(installed);
                }
            }
        }
        Ok(path.into())
    }
    pub(crate) fn configure_mcp(
        &self,
        kind: HarnessKind,
        path: &Path,
        bin: &str,
        socket: Option<&str>,
        dry_run: bool,
    ) -> Result<(), String> {
        if self.current_home_matches() {
            let override_dir = match kind {
                HarnessKind::Codex => std::env::var_os("CODEX_HOME").map(PathBuf::from),
                HarnessKind::Opencode => std::env::var_os("OPENCODE_CONFIG_DIR")
                    .map(PathBuf::from)
                    .or_else(|| {
                        std::env::var_os("XDG_CONFIG_HOME")
                            .map(|p| PathBuf::from(p).join("opencode"))
                    }),
                _ => None,
            };
            if let Some(directory) = override_dir {
                if crate::setup::canonical_dedup_key(&directory)
                    != crate::setup::canonical_dedup_key(
                        path.parent().ok_or("Invalid MCP config path")?,
                    )
                {
                    return Err(format!(
                        "Skillshare's {} environment selects {}; explicit account mapping is required before changing {}",
                        kind.as_str(),
                        directory.display(),
                        path.display()
                    ));
                }
            }
        }
        if kind == HarnessKind::Opencode && path.with_extension("jsonc").exists() {
            return Err("Existing OpenCode JSONC configuration needs explicit migration; preserved it instead of creating a second config".into());
        }
        self.ensure_initialized(dry_run)?;
        if dry_run {
            return Ok(());
        }
        let target = self.mcp_target.unwrap_or(kind.as_str());
        let original = match fs::read(path) {
            Ok(bytes) => Some(bytes),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e.to_string()),
        };
        let mut doc: Value = match original.as_deref() {
            Some(bytes) => serde_json::from_slice(bytes)
                .map_err(|_| "Invalid native JSON; Skillshare migration made no changes")?,
            None => json!({}),
        };
        let key = if kind == HarnessKind::Opencode {
            "mcp"
        } else {
            "mcpServers"
        };
        let servers = doc
            .as_object_mut()
            .ok_or("Native MCP config must be an object")?
            .entry(key)
            .or_insert_with(|| json!({}))
            .as_object_mut()
            .ok_or("Native MCP servers must be an object")?;
        let mut entry = servers.get("hyphae").cloned().unwrap_or_else(|| json!({}));
        let fields = entry
            .as_object_mut()
            .ok_or("Hyphae MCP entry must be an object")?;
        let command = if kind == HarnessKind::Opencode {
            fields
                .get("command")
                .and_then(Value::as_array)
                .and_then(|a| a.first())
                .and_then(Value::as_str)
        } else {
            fields.get("command").and_then(Value::as_str)
        };
        if let Some(command) = command {
            verify_command(command, bin)?;
        }
        // Optional env forwarding and other portable fields cannot be scoped to
        // one receiving client in Skillshare. Leave customized entries intact.
        for field in [
            "env",
            "environment",
            "headers",
            "url",
            "serverUrl",
            "httpUrl",
            "bearerToken",
            "disabled",
        ] {
            if fields.contains_key(field) {
                return Err(format!(
                    "Existing hyphae MCP field {field} requires explicit Skillshare migration; preserved user settings"
                ));
            }
        }
        if fields.get("enabled") == Some(&Value::Bool(false)) {
            return Err("Preserved disabled hyphae MCP entry; enable it explicitly before manager migration".into());
        }
        let previous: Vec<String> = if kind == HarnessKind::Opencode {
            fields
                .get("command")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .skip(1)
                        .filter_map(Value::as_str)
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default()
        } else {
            fields
                .get("args")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(Value::as_str)
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default()
        };
        let existing_args = previous.clone();
        let mut args = if previous.is_empty() {
            vec!["mcp".into()]
        } else {
            previous
        };
        if target == "claude-desktop" && !args.iter().any(|arg| arg == "--ephemeral") {
            args.push("--ephemeral".into());
        }
        if args.first().map(String::as_str) != Some("mcp") {
            return Err("Existing hyphae entry is not an MCP launch; preserved it".into());
        }
        if let Some(index) = args.iter().position(|a| a == "--backend") {
            let value = args
                .get(index + 1)
                .ok_or("Existing --backend has no value")?;
            if value != kind.as_str() {
                return Err("Existing explicit backend does not match the selected client; preserved its configuration".into());
            }
            args.drain(index..=index + 1);
        }
        if let Some(socket) = socket {
            if args.get(1).is_some_and(|a| !a.starts_with('-')) {
                args[1] = socket.into();
            } else {
                args.insert(1, socket.into());
            }
        }
        let plan = self.run(&["mcp", "list", "-g", "--json"])?;
        let changes = plan["changes"]
            .as_array()
            .ok_or("Skillshare returned no MCP plan; upgrade Skillshare")?;
        let mut targets: std::collections::BTreeSet<String> = changes
            .iter()
            .filter(|c| c["name"] == "hyphae" && c.get("root").is_none() && c["action"] != "remove")
            .filter_map(|c| c["target"].as_str().map(str::to_owned))
            .collect();
        let exists = !targets.is_empty();
        let state = self.home.join(".config/hyphae/skillshare/mcp/hyphae.json");
        if exists {
            let record: Option<Value> = fs::read(&state)
                .ok()
                .and_then(|b| serde_json::from_slice(&b).ok());
            let matching_existing = targets.contains(target)
                && changes
                    .iter()
                    .filter(|c| c["name"] == "hyphae" && c.get("root").is_none())
                    .all(|c| c["action"] == "unchanged" || c["action"] == "adopt");
            if record.is_none() && (!matching_existing || args != existing_args) {
                return Err("Skillshare already defines hyphae differently; resolve ownership before rerunning setup".into());
            }
            if record.is_some_and(|record| record["args"] != json!(args)) {
                return Err("Skillshare cannot represent different per-client channel/socket launch arguments under one hyphae definition; preserved existing registrations".into());
            }
        }
        let target_was_managed = targets.contains(target);
        targets.insert(target.into());
        if kind == HarnessKind::Opencode {
            fields.insert("type".into(), json!("local"));
            fields.insert(
                "command".into(),
                json!(
                    std::iter::once(bin.to_owned())
                        .chain(args.clone())
                        .collect::<Vec<_>>()
                ),
            );
        } else {
            fields.insert("command".into(), json!(bin));
            fields.insert("args".into(), json!(args));
            fields.insert("type".into(), json!("stdio"));
        }
        let had_native = servers.contains_key("hyphae");
        if had_native {
            servers.insert("hyphae".into(), entry);
        }
        let updated = serde_json::to_vec_pretty(&doc).map_err(|e| e.to_string())?;
        // A recognized direct entry is normalized once before Skillshare adopts
        // it. The server name and all native-only user fields stay in place.
        if had_native && !target_was_managed {
            write_atomic_file(path, &updated, false)?;
        }
        if !exists {
            write_atomic_file(
                &state,
                &serde_json::to_vec(&json!({"args":args})).map_err(|e| e.to_string())?,
                true,
            )?;
        }
        let mut command = vec![
            "mcp",
            if exists { "edit" } else { "add" },
            "hyphae",
            "-g",
            "--json",
            "--sync",
        ];
        for target in &targets {
            command.extend(["--target", target]);
        }
        command.extend(["--", bin]);
        command.extend(args.iter().map(String::as_str));
        let result = self.run(&command);
        if result.is_err() && had_native && !target_was_managed {
            if let Some(bytes) = &original {
                write_atomic_file(path, bytes, false)?;
            }
        }
        result?;
        if !path.is_file() {
            return Err(format!(
                "Skillshare did not create {}; no direct fallback attempted",
                path.display()
            ));
        }
        write_atomic_file(
            &state,
            &serde_json::to_vec(&json!({"args":args})).map_err(|e| e.to_string())?,
            true,
        )?;
        Ok(())
    }
    pub(crate) fn detect(home: &Path) -> Option<Self> {
        let executable = find_in_path(
            Path::new("skillshare"),
            &std::env::var_os("PATH")?,
            PathSearchPolicy {
                include_empty: false,
                executable: true,
                windows_suffixes: WindowsSuffixes::PathExt,
            },
        )?;
        Some(Self {
            executable,
            home: home.into(),
            mcp_target: None,
        })
    }

    fn command(&self) -> Command {
        let mut command = Command::new(&self.executable);
        command
            .env("HOME", &self.home)
            .env("SKILLSHARE_AUTO_UPDATE_CHECK", "false")
            .stdin(Stdio::null());
        #[cfg(windows)]
        command.env("USERPROFILE", &self.home);
        if !self.current_home_matches() {
            for key in [
                "XDG_CONFIG_HOME",
                "XDG_DATA_HOME",
                "XDG_STATE_HOME",
                "XDG_CACHE_HOME",
                "SKILLSHARE_CONFIG",
                "CODEX_HOME",
                "CLAUDE_CONFIG_DIR",
                "OPENCODE_CONFIG_DIR",
                "PI_CODING_AGENT_DIR",
            ] {
                command.env_remove(key);
            }
            #[cfg(windows)]
            {
                command.env("APPDATA", self.home.join("AppData/Roaming"));
                command.env("LOCALAPPDATA", self.home.join("AppData/Local"));
                command.env(
                    "SKILLSHARE_CONFIG",
                    self.home.join(".config/skillshare/config.yaml"),
                );
            }
        }
        command
    }

    pub(crate) fn run(&self, args: &[&str]) -> Result<Value, String> {
        let mut child = self
            .command()
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("Skillshare could not start: {e}"))?;
        let mut stdout = child.stdout.take().ok_or("Skillshare stdout unavailable")?;
        let reader = std::thread::spawn(move || {
            let mut bytes = Vec::new();
            (&mut stdout)
                .take(4 * 1024 * 1024)
                .read_to_end(&mut bytes)?;
            std::io::copy(&mut stdout, &mut std::io::sink())?;
            Ok::<_, std::io::Error>(bytes)
        });
        let started = std::time::Instant::now();
        let status = loop {
            if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
                break status;
            }
            if started.elapsed() > std::time::Duration::from_secs(30) {
                let _ = child.kill();
                let _ = child.wait();
                return Err("Skillshare timed out after 30 seconds; inspect `skillshare doctor -g` before retrying. No direct installation was attempted.".into());
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        };
        let stdout = reader
            .join()
            .map_err(|_| "Skillshare output reader failed")?
            .map_err(|e| e.to_string())?;
        if !status.success() {
            // Manager output may contain user-owned settings or credential hints.
            // Keep it out of the CLI envelope and give an exact diagnostic command.
            return Err(format!(
                "Skillshare failed ({}). Inspect `skillshare {} -g --no-tui`; no direct installation was attempted.",
                status,
                args.first().unwrap_or(&"doctor")
            ));
        }
        Ok(serde_json::from_slice(&stdout).unwrap_or(Value::Null))
    }

    fn config_path(&self) -> PathBuf {
        if self.current_home_matches() {
            if let Some(path) = std::env::var_os("SKILLSHARE_CONFIG") {
                return path.into();
            }
            if let Some(path) = std::env::var_os("XDG_CONFIG_HOME") {
                return PathBuf::from(path).join("skillshare/config.yaml");
            }
            #[cfg(windows)]
            if let Some(path) = std::env::var_os("APPDATA") {
                return PathBuf::from(path).join("skillshare/config.yaml");
            }
        }
        self.home.join(".config/skillshare/config.yaml")
    }

    pub(crate) fn ensure_initialized(&self, dry_run: bool) -> Result<(), String> {
        if self.config_path().exists() || dry_run {
            return Ok(());
        }
        self.run(&[
            "init",
            "-g",
            "--no-copy",
            "--no-targets",
            "--no-git",
            "--no-skill",
        ])?;
        Ok(())
    }

    /// Install one generated skill through the manager, respecting the receiving
    /// target's naming, filters and sync mode. Local staging persists for updates.
    pub(crate) fn install_skill(
        &self,
        path: &Path,
        text: &str,
        force: bool,
        dry_run: bool,
    ) -> Result<PathBuf, String> {
        self.ensure_initialized(dry_run)?;
        if dry_run {
            return Ok(path.into());
        }
        let skill_dir = path.parent().ok_or("Skill path has no directory")?;
        let target_dir = skill_dir
            .parent()
            .ok_or("Skill path has no target directory")?;
        let name = skill_dir
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or("Invalid skill name")?;
        let installed = self.resolve_skill_path(path)?;
        if installed != path
            && !force
            && fs::read_to_string(&installed)
                .is_ok_and(|text| text.contains(crate::skill_render::UNMANAGED_MARKER))
        {
            return Err(format!(
                "Preserved unmanaged Skillshare skill at {}; pass --force-skills to overwrite",
                installed.display()
            ));
        }
        let old = fs::read_to_string(path).ok();
        if let Some(old) = &old {
            if (old.contains(crate::skill_render::UNMANAGED_MARKER) && !force)
                || !(old
                    .lines()
                    .any(|line| line.starts_with(crate::skill_render::MANAGED_MARKER_PREFIX))
                    || old == crate::wizard::HYPHAE_SETUP_SKILL_MD
                    || old.contains("metadata:\n  targets:"))
            {
                return Err(format!(
                    "Preserved customized skill at {}; resolve it before Skillshare migration",
                    path.display()
                ));
            }
        }
        let id = &hyp_store::sha256_hex(
            crate::setup::canonical_dedup_key(target_dir)
                .to_string_lossy()
                .as_bytes(),
        )[..12];
        let inventory = self.run(&["target", "list", "-g", "--json"])?;
        let targets = inventory["targets"]
            .as_array()
            .ok_or("Skillshare returned no target inventory; upgrade Skillshare")?;
        let target = targets.iter().find(|target| {
            target["path"].as_str().is_some_and(|p| {
                crate::setup::canonical_dedup_key(Path::new(p))
                    == crate::setup::canonical_dedup_key(target_dir)
            })
        });
        let target_name;
        let naming;
        if let Some(target) = target {
            if target["skillsEnabled"] == false {
                return Err(format!(
                    "Skillshare skills are disabled for {}; enable them in Skillshare first",
                    target_dir.display()
                ));
            }
            target_name = target["name"]
                .as_str()
                .ok_or("Skillshare target has no name")?
                .to_owned();
            naming = target["targetNaming"].as_str().unwrap_or("flat").to_owned();
        } else {
            target_name = format!("hyphae-{id}");
            fs::create_dir_all(target_dir).map_err(|e| e.to_string())?;
            self.run(&[
                "target",
                "add",
                &target_name,
                &target_dir.to_string_lossy(),
                "-g",
            ])?;
            naming = "flat".into();
        }
        let collection = format!("hyphae-{id}");
        let staged = self
            .home
            .join(".config/hyphae/skillshare")
            .join(&collection)
            .join(name)
            .join("SKILL.md");
        let targets_yaml = serde_json::to_string(&vec![&target_name]).map_err(|e| e.to_string())?;
        let rendered = text.replacen(
            "---\n",
            &format!("---\nmetadata:\n  targets: {targets_yaml}\n"),
            1,
        );
        write_atomic_file(&staged, rendered.as_bytes(), false)?;
        self.run(&[
            "install",
            &staged.parent().unwrap().to_string_lossy(),
            "--into",
            &collection,
            "--update",
            "-g",
            "--json",
        ])?;
        let destination = if naming == "flat" {
            target_dir.join(format!("{collection}__{name}/SKILL.md"))
        } else {
            target_dir.join(name).join("SKILL.md")
        };
        let backup = staged.parent().unwrap().with_extension("direct-backup");
        let move_direct = old.is_some()
            && destination == path
            && fs::symlink_metadata(skill_dir).is_ok_and(|m| !m.file_type().is_symlink());
        if move_direct {
            if fs::read_dir(skill_dir).map_err(|e| e.to_string())?.count() != 1 {
                return Err(format!(
                    "Preserved extra files in {}; migrate them into Skillshare before setup",
                    skill_dir.display()
                ));
            }
            if backup.exists() {
                return Err(format!(
                    "Unresolved skill migration backup at {}; restore or remove it first",
                    backup.display()
                ));
            }
            fs::rename(skill_dir, &backup).map_err(|e| e.to_string())?;
        }
        let sync = self.run(&["sync", "-g", "--json"]);
        if sync.is_err() && move_direct && !skill_dir.exists() {
            fs::rename(&backup, skill_dir).map_err(|e| e.to_string())?;
        }
        sync?;
        if !destination.is_file() {
            if move_direct && !skill_dir.exists() {
                fs::rename(&backup, skill_dir).map_err(|e| e.to_string())?;
            }
            return Err(format!(
                "Skillshare did not expose {name} at {}; inspect target filters and naming with `skillshare target {target_name} -g`",
                destination.display()
            ));
        }
        if move_direct {
            fs::remove_dir_all(&backup).map_err(|e| e.to_string())?;
        }
        if destination != path && path.is_file() {
            let old = fs::read_to_string(path).map_err(|e| e.to_string())?;
            if old.contains(crate::skill_render::UNMANAGED_MARKER) && !force {
                return Err(format!(
                    "Preserved unmanaged skill at {}; remove the conflict before Skillshare migration",
                    path.display()
                ));
            }
            if old
                .lines()
                .any(|line| line.starts_with(crate::skill_render::MANAGED_MARKER_PREFIX))
                || old == crate::wizard::HYPHAE_SETUP_SKILL_MD
            {
                if fs::symlink_metadata(skill_dir).is_ok_and(|m| m.file_type().is_symlink()) {
                    fs::remove_file(skill_dir).map_err(|e| e.to_string())?;
                } else {
                    fs::remove_file(path).map_err(|e| e.to_string())?;
                    let _ = fs::remove_dir(skill_dir);
                }
            } else {
                return Err(format!(
                    "Preserved customized skill at {}; resolve it before Skillshare migration",
                    path.display()
                ));
            }
        }
        write_atomic_file(
            &self.skill_record(path),
            &serde_json::to_vec(&json!({"path": destination})).map_err(|e| e.to_string())?,
            false,
        )?;
        Ok(destination)
    }
}

fn verify_command(command: &str, bin: &str) -> Result<(), String> {
    if command == bin
        || Path::new(command)
            .file_name()
            .is_some_and(|name| name == "hyp" || name == "hyp.exe")
    {
        Ok(())
    } else {
        Err("The existing hyphae entry runs a different command; preserved it instead of claiming ownership".into())
    }
}
