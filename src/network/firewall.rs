//! Windows Firewall integration via netsh advfirewall.
//!
//! Provides: rule enumeration, block/allow per-app, lockdown mode,
//! and ask-to-connect mode tracking.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, Mutex};

use crate::types::{FirewallAction, FirewallAppAction, FirewallDirection, FirewallMode, FirewallProfile, FirewallRule};

/// Manages firewall state and rules.
pub struct FirewallManager {
    /// Cached firewall rules.
    pub rules: Vec<FirewallRule>,
    /// Current firewall mode.
    pub mode: FirewallMode,
    /// Apps that have been approved in ask-to-connect mode.
    pub approved_apps: HashSet<String>,
    /// Apps that have been blocked in ask-to-connect mode.
    pub blocked_apps: HashSet<String>,
    /// Apps pending approval (detected in current session but not yet approved).
    pub pending_apps: Vec<String>,
    /// Whether the firewall is globally enabled.
    pub enabled: bool,
    /// Scroll position for UI.
    pub scroll_offset: usize,
    /// Ticks since last rule refresh.
    refresh_tick: u32,
    /// Filter text for rules.
    pub filter_text: String,
    /// Background refresh result (rules, enabled).
    refresh_result: Arc<Mutex<Option<(Vec<FirewallRule>, bool)>>>,
    /// Saved firewall profiles.
    pub profiles: Vec<FirewallProfile>,
    /// Currently active profile name.
    pub active_profile: Option<String>,
    /// Path to the profiles persistence file.
    profiles_path: PathBuf,
    /// Per-app actions managed by PSNET (persisted to disk).
    pub app_actions: HashMap<String, FirewallAppAction>,
    /// Path to the app action state file.
    state_path: PathBuf,
}

impl FirewallManager {
    pub fn new() -> Self {
        // Defer is_firewall_enabled() — it runs `netsh` which blocks 100-500ms.
        // Start with enabled=true (safe default), fix on first background tick.
        let state_path = Self::default_state_path();
        let app_actions = Self::load_state_from_disk(&state_path);
        let blocked_apps: HashSet<String> = app_actions.iter()
            .filter(|(_, a)| matches!(a, FirewallAppAction::Deny | FirewallAppAction::Drop))
            .map(|(name, _)| name.clone())
            .collect();
        let approved_apps: HashSet<String> = app_actions.iter()
            .filter(|(_, a)| matches!(a, FirewallAppAction::Allow))
            .map(|(name, _)| name.clone())
            .collect();
        Self {
            rules: Vec::new(),
            mode: FirewallMode::Normal,
            approved_apps,
            blocked_apps,
            pending_apps: Vec::new(),
            enabled: true, // assume enabled; background check will correct
            scroll_offset: 0,
            refresh_tick: 0,
            filter_text: String::new(),
            refresh_result: Arc::new(Mutex::new(None)),
            profiles: Vec::new(), // loaded lazily on first access
            active_profile: None,
            profiles_path: Self::default_profiles_path(),
            app_actions,
            state_path,
        }
    }

    /// Default path: %APPDATA%/psnet/firewall_profiles.json
    fn default_profiles_path() -> PathBuf {
        if let Some(data_dir) = dirs::data_dir() {
            let dir = data_dir.join("psnet");
            let _ = std::fs::create_dir_all(&dir);
            dir.join("firewall_profiles.json")
        } else {
            PathBuf::from("psnet_firewall_profiles.json")
        }
    }

    /// Default path: %APPDATA%/psnet/firewall_state.json
    fn default_state_path() -> PathBuf {
        if let Some(data_dir) = dirs::data_dir() {
            let dir = data_dir.join("psnet");
            let _ = std::fs::create_dir_all(&dir);
            dir.join("firewall_state.json")
        } else {
            PathBuf::from("psnet_firewall_state.json")
        }
    }

    fn load_state_from_disk(path: &PathBuf) -> HashMap<String, FirewallAppAction> {
        match std::fs::read_to_string(path) {
            Ok(content) => serde_json::from_str(&content).unwrap_or_default(),
            Err(_) => HashMap::new(),
        }
    }

    fn save_state_to_disk(&self) {
        if let Ok(json) = serde_json::to_string_pretty(&self.app_actions) {
            let _ = std::fs::write(&self.state_path, json);
        }
    }

    fn load_profiles_from_disk(path: &PathBuf) -> Vec<FirewallProfile> {
        match std::fs::read_to_string(path) {
            Ok(content) => serde_json::from_str(&content).unwrap_or_default(),
            Err(_) => Vec::new(),
        }
    }

    fn save_profiles_to_disk(&self) {
        if let Ok(json) = serde_json::to_string_pretty(&self.profiles) {
            let _ = std::fs::write(&self.profiles_path, json);
        }
    }

    /// Refresh rules from system. Periodic refresh runs on a background thread
    /// to avoid blocking the UI for 2-5 seconds while netsh executes.
    pub fn tick(&mut self) {
        self.refresh_tick += 1;

        // Poll background refresh result
        if let Ok(mut r) = self.refresh_result.lock() {
            if let Some((rules, enabled)) = r.take() {
                self.rules = rules;
                self.enabled = enabled;
            }
        }

        // Spawn background refresh every 30 ticks
        if self.refresh_tick % 30 == 1 {
            let result = Arc::clone(&self.refresh_result);
            std::thread::spawn(move || {
                let rules = fetch_firewall_rules();
                let enabled = is_firewall_enabled();
                if let Ok(mut r) = result.lock() {
                    *r = Some((rules, enabled));
                }
            });
        }
    }

    /// Fetch current firewall rules from the system (blocking — use for user-initiated refresh).
    pub fn refresh_rules(&mut self) {
        self.rules = fetch_firewall_rules();
        self.enabled = is_firewall_enabled();
    }

    /// Block an application by creating outbound + inbound block rules.
    ///
    /// `process_path` should be the **full executable path**
    /// (e.g. `C:\Program Files\Google\Chrome\Application\chrome.exe`).
    /// Windows Firewall silently ignores the `program=` filter when only
    /// a filename is given — the full path is required for the rule to match.
    pub fn block_app(&mut self, process_path: &str) -> bool {
        self.apply_action(process_path, Some(process_path), FirewallAppAction::Deny)
    }

    /// Unblock an application (removes all PSNET rules for this app).
    pub fn unblock_app(&mut self, app_name: &str) -> bool {
        let base = app_name.rsplit('\\').next().unwrap_or(app_name);
        let key = base.to_lowercase();
        self.remove_psnet_rules(base);
        self.blocked_apps.remove(&key);
        self.approved_apps.remove(&key);
        self.app_actions.remove(&key);
        self.save_state_to_disk();
        self.refresh_rules();
        true
    }

    /// Enable lockdown mode — block all outbound except approved.
    pub fn enable_lockdown(&mut self) -> bool {
        let result = Command::new("netsh")
            .args([
                "advfirewall", "set", "allprofiles",
                "firewallpolicy", "blockinbound,blockoutbound",
            ])
            .output();

        if let Ok(out) = result {
            if out.status.success() {
                self.mode = FirewallMode::Lockdown;
                return true;
            }
        }
        false
    }

    /// Disable lockdown mode — restore normal policy.
    pub fn disable_lockdown(&mut self) -> bool {
        let result = Command::new("netsh")
            .args([
                "advfirewall", "set", "allprofiles",
                "firewallpolicy", "blockinbound,allowoutbound",
            ])
            .output();

        if let Ok(out) = result {
            if out.status.success() {
                self.mode = FirewallMode::Normal;
                return true;
            }
        }
        false
    }

    /// Toggle ask-to-connect mode (tracking only — no actual firewall changes).
    pub fn toggle_ask_to_connect(&mut self) {
        self.mode = match self.mode {
            FirewallMode::AskToConnect => FirewallMode::Normal,
            _ => FirewallMode::AskToConnect,
        };
    }

    /// In ask-to-connect mode, check if a process is pending approval.
    pub fn check_pending(&mut self, process_name: &str) {
        if self.mode != FirewallMode::AskToConnect {
            return;
        }
        let key = process_name.to_lowercase();
        if !self.approved_apps.contains(&key) && !self.blocked_apps.contains(&key) {
            if !self.pending_apps.contains(&key) {
                self.pending_apps.push(key);
            }
        }
    }

    /// Approve a pending app in ask-to-connect mode.
    pub fn approve_pending(&mut self, index: usize) {
        if let Some(app) = self.pending_apps.get(index).cloned() {
            self.approved_apps.insert(app);
            self.pending_apps.remove(index);
        }
    }

    /// Block a pending app in ask-to-connect mode.
    pub fn block_pending(&mut self, index: usize) {
        if let Some(app) = self.pending_apps.get(index).cloned() {
            self.blocked_apps.insert(app);
            self.pending_apps.remove(index);
        }
    }

    /// Save the current blocked/approved apps and mode as a named profile.
    pub fn save_profile(&mut self, name: &str) {
        let profile = FirewallProfile {
            name: name.to_string(),
            blocked_apps: self.blocked_apps.iter().cloned().collect(),
            allowed_apps: self.approved_apps.iter().cloned().collect(),
            mode: self.mode.clone(),
        };

        // Replace existing profile with the same name, or push new
        if let Some(existing) = self.profiles.iter_mut().find(|p| p.name == name) {
            *existing = profile;
        } else {
            self.profiles.push(profile);
        }

        self.active_profile = Some(name.to_string());
        self.save_profiles_to_disk();
    }

    /// Apply a saved profile by name: sets blocked/approved apps and firewall mode.
    pub fn load_profile(&mut self, name: &str) -> bool {
        let profile = match self.profiles.iter().find(|p| p.name == name) {
            Some(p) => p.clone(),
            None => return false,
        };

        // Clear current state
        self.blocked_apps.clear();
        self.approved_apps.clear();

        // Apply profile's blocked apps
        for app in &profile.blocked_apps {
            self.blocked_apps.insert(app.clone());
        }
        // Apply profile's allowed apps
        for app in &profile.allowed_apps {
            self.approved_apps.insert(app.clone());
        }
        // Apply mode
        self.mode = profile.mode;

        self.active_profile = Some(name.to_string());
        true
    }

    /// Delete a saved profile by name.
    pub fn delete_profile(&mut self, name: &str) {
        self.profiles.retain(|p| p.name != name);
        if self.active_profile.as_deref() == Some(name) {
            self.active_profile = None;
        }
        self.save_profiles_to_disk();
    }

    /// List all saved profiles.
    pub fn list_profiles(&self) -> &[FirewallProfile] {
        &self.profiles
    }

    /// Check if an app is blocked by a PSNET-created rule (Deny or Drop).
    pub fn is_psnet_blocked(&self, app_name: &str) -> bool {
        let key = app_name.to_lowercase();
        if self.blocked_apps.contains(&key) {
            return true;
        }
        let block_name = format!("PSNET_Block_{}", app_name);
        let drop_name = format!("PSNET_Drop_{}", app_name);
        self.rules.iter().any(|r| {
            r.enabled && (r.name.eq_ignore_ascii_case(&block_name) || r.name.eq_ignore_ascii_case(&drop_name))
        })
    }

    /// Toggle block/unblock for an app.
    /// `process_path` is the full executable path; if None, falls back to app_name
    /// (less reliable — prefer always passing a full path).
    pub fn toggle_block(&mut self, app_name: &str, process_path: Option<&str>) -> bool {
        if self.is_psnet_blocked(app_name) {
            self.unblock_app(app_name)
        } else {
            self.block_app(process_path.unwrap_or(app_name))
        }
    }

    /// Apply a firewall action (Allow / Deny / Drop) for an app.
    /// Removes any previous PSNET rules for this app first, then creates new ones.
    pub fn apply_action(&mut self, app_name: &str, process_path: Option<&str>, action: FirewallAppAction) -> bool {
        let base = app_name.rsplit('\\').next().unwrap_or(app_name);
        let key = base.to_lowercase();

        // Remove any existing PSNET rules for this app
        self.remove_psnet_rules(base);

        let path = process_path.unwrap_or(app_name);

        let ok = match &action {
            FirewallAppAction::Allow => {
                // Create explicit allow rules
                let rule_out = format!("PSNET_Allow_{}", base);
                let rule_in = format!("PSNET_Allow_{}_In", base);
                let ok = netsh_add_rule(&rule_out, "out", "allow", path);
                let _ = netsh_add_rule(&rule_in, "in", "allow", path);
                ok
            }
            FirewallAppAction::Deny => {
                let rule_out = format!("PSNET_Block_{}", base);
                let rule_in = format!("PSNET_Block_{}_In", base);
                let ok = netsh_add_rule(&rule_out, "out", "block", path);
                let _ = netsh_add_rule(&rule_in, "in", "block", path);
                ok
            }
            FirewallAppAction::Drop => {
                let rule_out = format!("PSNET_Drop_{}", base);
                let rule_in = format!("PSNET_Drop_{}_In", base);
                let ok = netsh_add_rule(&rule_out, "out", "block", path);
                let _ = netsh_add_rule(&rule_in, "in", "block", path);
                ok
            }
        };

        if ok {
            // Update in-memory tracking
            self.blocked_apps.remove(&key);
            self.approved_apps.remove(&key);
            match &action {
                FirewallAppAction::Deny | FirewallAppAction::Drop => {
                    self.blocked_apps.insert(key.clone());
                }
                FirewallAppAction::Allow => {
                    self.approved_apps.insert(key.clone());
                }
            }
            self.app_actions.insert(key, action);
            self.save_state_to_disk();
            self.refresh_rules();
        }
        ok
    }

    /// Remove all PSNET-created rules (Block, Allow, Drop) for a specific app.
    fn remove_psnet_rules(&mut self, app_name: &str) {
        for prefix in &["PSNET_Block_", "PSNET_Allow_", "PSNET_Drop_"] {
            let rule = format!("{}{}", prefix, app_name);
            let rule_in = format!("{}{}_In", prefix, app_name);
            let _ = netsh_delete_rule(&rule);
            let _ = netsh_delete_rule(&rule_in);
        }
    }

    /// Remove ALL PSNET firewall rules and reset state to defaults.
    pub fn reset_all_psnet_rules(&mut self) {
        // Collect app names before clearing
        let apps: Vec<String> = self.app_actions.keys().cloned().collect();
        for key in &apps {
            // Try to find the original-case name from rules
            let base = key.rsplit('\\').next().unwrap_or(key);
            self.remove_psnet_rules(base);
        }
        // Also scan rules for any PSNET_* rules we might have missed
        for rule in &self.rules {
            if rule.name.starts_with("PSNET_") {
                let _ = netsh_delete_rule(&rule.name);
            }
        }
        self.app_actions.clear();
        self.blocked_apps.clear();
        self.approved_apps.clear();
        self.mode = FirewallMode::Normal;
        self.save_state_to_disk();
        self.refresh_rules();
    }

    /// Get the current PSNET action for an app, if any.
    pub fn get_app_action(&self, app_name: &str) -> Option<&FirewallAppAction> {
        self.app_actions.get(&app_name.to_lowercase())
    }

    /// Filter rules for display.
    pub fn filtered_rules(&self) -> Vec<&FirewallRule> {
        if self.filter_text.is_empty() {
            self.rules.iter().collect()
        } else {
            let ft = self.filter_text.to_lowercase();
            self.rules.iter()
                .filter(|r| {
                    r.name.to_lowercase().contains(&ft)
                        || r.process_name.as_ref().map(|p| p.to_lowercase().contains(&ft)).unwrap_or(false)
                        || r.action.label().to_lowercase().contains(&ft)
                        || r.profile.to_lowercase().contains(&ft)
                })
                .collect()
        }
    }
}

// ─── Netsh helpers ───────────────────────────────────────────────────────────

fn netsh_add_rule(name: &str, dir: &str, action: &str, program: &str) -> bool {
    Command::new("netsh")
        .args([
            "advfirewall", "firewall", "add", "rule",
            &format!("name={}", name),
            &format!("dir={}", dir),
            &format!("action={}", action),
            &format!("program={}", program),
            "enable=yes",
            "profile=any",
        ])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn netsh_delete_rule(name: &str) -> bool {
    Command::new("netsh")
        .args([
            "advfirewall", "firewall", "delete", "rule",
            &format!("name={}", name),
        ])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

// ─── System queries ──────────────────────────────────────────────────────────

/// Check if Windows Firewall is enabled.
fn is_firewall_enabled() -> bool {
    let output = Command::new("netsh")
        .args(["advfirewall", "show", "allprofiles", "state"])
        .output();

    match output {
        Ok(o) if o.status.success() => {
            let text = String::from_utf8_lossy(&o.stdout);
            text.contains("ON")
        }
        _ => false,
    }
}

/// Fetch firewall rules from netsh.
fn fetch_firewall_rules() -> Vec<FirewallRule> {
    let output = Command::new("netsh")
        .args(["advfirewall", "firewall", "show", "rule", "name=all", "verbose"])
        .output();

    let output = match output {
        Ok(o) if o.status.success() => o,
        _ => return Vec::new(),
    };

    let text = String::from_utf8_lossy(&output.stdout);
    parse_firewall_rules(&text)
}

fn parse_firewall_rules(text: &str) -> Vec<FirewallRule> {
    let mut rules = Vec::new();
    let mut current_name = String::new();
    let mut current_action = FirewallAction::Allow;
    let mut current_direction = FirewallDirection::Inbound;
    let mut current_enabled = true;
    let mut current_program: Option<String> = None;
    let mut current_profile = String::new();
    let mut in_rule = false;

    for line in text.lines() {
        let trimmed = line.trim();

        if trimmed.starts_with("Rule Name:") {
            // Save previous rule
            if in_rule && !current_name.is_empty() {
                rules.push(FirewallRule {
                    name: current_name.clone(),
                    process_name: current_program.take(),
                    action: current_action.clone(),
                    direction: current_direction.clone(),
                    enabled: current_enabled,
                    profile: current_profile.clone(),
                });
            }
            current_name = trimmed.splitn(2, ':').nth(1).unwrap_or("").trim().to_string();
            current_program = None;
            current_enabled = true;
            current_profile.clear();
            in_rule = true;
        } else if trimmed.starts_with("Action:") {
            let val = trimmed.splitn(2, ':').nth(1).unwrap_or("").trim();
            current_action = if val.eq_ignore_ascii_case("block") {
                FirewallAction::Block
            } else {
                FirewallAction::Allow
            };
        } else if trimmed.starts_with("Direction:") {
            let val = trimmed.splitn(2, ':').nth(1).unwrap_or("").trim();
            current_direction = if val.eq_ignore_ascii_case("in") {
                FirewallDirection::Inbound
            } else {
                FirewallDirection::Outbound
            };
        } else if trimmed.starts_with("Enabled:") {
            let val = trimmed.splitn(2, ':').nth(1).unwrap_or("").trim();
            current_enabled = val.eq_ignore_ascii_case("yes");
        } else if trimmed.starts_with("Program:") {
            let val = trimmed.splitn(2, ':').nth(1).unwrap_or("").trim();
            if !val.eq_ignore_ascii_case("any") && !val.is_empty() {
                current_program = Some(val.to_string());
            }
        } else if trimmed.starts_with("Profiles:") {
            current_profile = trimmed.splitn(2, ':').nth(1).unwrap_or("").trim().to_string();
        }
    }

    // Push the last rule
    if in_rule && !current_name.is_empty() {
        rules.push(FirewallRule {
            name: current_name,
            process_name: current_program,
            action: current_action,
            direction: current_direction,
            enabled: current_enabled,
            profile: current_profile,
        });
    }

    rules
}
