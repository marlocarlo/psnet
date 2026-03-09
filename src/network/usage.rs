//! Data plan monitoring and usage persistence.
//!
//! Tracks daily upload/download totals per-app and persists to a JSON file.
//! Supports data plan limits with overage alerts.

use std::collections::HashMap;
use std::path::PathBuf;

use chrono::Local;

use crate::types::{DataPlan, UsageRecord, UsageStore};

/// Manages data usage tracking and persistence.
pub struct UsageTracker {
    /// Persistent store.
    pub store: UsageStore,
    /// Path to the JSON persistence file.
    data_path: PathBuf,
    /// Today's date string.
    today: String,
    /// Dirty flag — needs save.
    dirty: bool,
    /// Ticks since last save.
    save_tick: u32,
    /// Running session totals (for delta calculation).
    session_down: u64,
    session_up: u64,
    /// Per-app session totals.
    session_per_app: HashMap<String, (u64, u64)>,
}

impl UsageTracker {
    pub fn new() -> Self {
        let data_path = Self::default_data_path();
        let store = Self::load_or_default(&data_path);
        let today = Local::now().format("%Y-%m-%d").to_string();

        Self {
            store,
            data_path,
            today,
            dirty: false,
            save_tick: 0,
            session_down: 0,
            session_up: 0,
            session_per_app: HashMap::new(),
        }
    }

    /// Default path: %APPDATA%/psnet/usage.json
    fn default_data_path() -> PathBuf {
        if let Some(data_dir) = dirs::data_dir() {
            let dir = data_dir.join("psnet");
            let _ = std::fs::create_dir_all(&dir);
            dir.join("usage.json")
        } else {
            PathBuf::from("psnet_usage.json")
        }
    }

    fn load_or_default(path: &PathBuf) -> UsageStore {
        match std::fs::read_to_string(path) {
            Ok(content) => serde_json::from_str(&content).unwrap_or_default(),
            Err(_) => UsageStore::default(),
        }
    }

    /// Update with the current session's total bytes.
    /// Call each tick with the cumulative totals from the app.
    pub fn update(
        &mut self,
        total_down: u64,
        total_up: u64,
        per_app: &HashMap<String, (u64, u64)>,
    ) {
        let today = Local::now().format("%Y-%m-%d").to_string();

        // Day rollover check
        if today != self.today {
            self.today = today.clone();
            // Reset session tracking for new day
            self.session_down = 0;
            self.session_up = 0;
            self.session_per_app.clear();
        }

        // Calculate deltas since last tick
        let delta_down = total_down.saturating_sub(self.session_down);
        let delta_up = total_up.saturating_sub(self.session_up);
        self.session_down = total_down;
        self.session_up = total_up;

        // Find or create today's record
        let record = if let Some(rec) = self.store.daily_records.iter_mut().find(|r| r.date == today) {
            rec
        } else {
            self.store.daily_records.push(UsageRecord {
                date: today.clone(),
                download_bytes: 0,
                upload_bytes: 0,
                per_app: HashMap::new(),
            });
            self.store.daily_records.last_mut().unwrap()
        };

        record.download_bytes += delta_down;
        record.upload_bytes += delta_up;

        // Update per-app deltas
        for (name, &(down, up)) in per_app {
            let prev = self.session_per_app.entry(name.clone()).or_insert((0, 0));
            let app_delta_down = down.saturating_sub(prev.0);
            let app_delta_up = up.saturating_sub(prev.1);
            *prev = (down, up);

            let entry = record.per_app.entry(name.clone()).or_insert((0, 0));
            entry.0 += app_delta_down;
            entry.1 += app_delta_up;
        }

        if delta_down > 0 || delta_up > 0 {
            self.dirty = true;
        }

        // Prune old records (keep 90 days)
        if self.store.daily_records.len() > 90 {
            self.store.daily_records.drain(0..self.store.daily_records.len() - 90);
        }

        // Auto-save periodically
        self.save_tick += 1;
        if self.dirty && self.save_tick % 60 == 0 {
            self.save();
        }
    }

    /// Force save to disk.
    pub fn save(&mut self) {
        if let Ok(json) = serde_json::to_string_pretty(&self.store) {
            let _ = std::fs::write(&self.data_path, json);
            self.dirty = false;
        }
    }

    /// Get today's total usage.
    pub fn today_usage(&self) -> (u64, u64) {
        self.store.daily_records.iter()
            .find(|r| r.date == self.today)
            .map(|r| (r.download_bytes, r.upload_bytes))
            .unwrap_or((0, 0))
    }

    /// Get this month's total usage (for data plan comparison).
    pub fn month_usage(&self) -> (u64, u64) {
        let month_prefix = &self.today[..7]; // YYYY-MM
        self.store.daily_records.iter()
            .filter(|r| r.date.starts_with(month_prefix))
            .fold((0, 0), |(d, u), r| (d + r.download_bytes, u + r.upload_bytes))
    }

    /// Get data plan.
    pub fn data_plan(&self) -> &DataPlan {
        &self.store.data_plan
    }

    /// Update data plan settings.
    pub fn set_data_plan(&mut self, plan: DataPlan) {
        self.store.data_plan = plan;
        self.dirty = true;
    }

    /// Get daily records for the last N days.
    pub fn recent_days(&self, n: usize) -> Vec<&UsageRecord> {
        let len = self.store.daily_records.len();
        let start = len.saturating_sub(n);
        self.store.daily_records[start..].iter().collect()
    }

    /// Export usage data to a CSV file.
    ///
    /// Writes daily records as `date,download_bytes,upload_bytes` followed by
    /// a per-app section with `date,app,download_bytes,upload_bytes`.
    pub fn export_csv(&self, path: &str) -> Result<(), std::io::Error> {
        use std::io::Write;
        let mut file = std::fs::File::create(path)?;

        // Daily totals section
        writeln!(file, "date,download_bytes,upload_bytes")?;
        for record in &self.store.daily_records {
            writeln!(file, "{},{},{}", record.date, record.download_bytes, record.upload_bytes)?;
        }

        // Per-app section
        writeln!(file)?;
        writeln!(file, "date,app,download_bytes,upload_bytes")?;
        for record in &self.store.daily_records {
            let mut apps: Vec<_> = record.per_app.iter().collect();
            apps.sort_by_key(|(name, _)| name.clone());
            for (name, (down, up)) in apps {
                writeln!(file, "{},{},{},{}", record.date, name, down, up)?;
            }
        }

        Ok(())
    }

    /// Check if data plan limit is exceeded or near threshold.
    /// Returns (used, limit, percentage).
    pub fn plan_status(&self) -> (u64, u64, u8) {
        let (month_down, month_up) = self.month_usage();
        let used = month_down + month_up;
        let limit = self.store.data_plan.limit_bytes;
        let pct = if limit > 0 {
            ((used as f64 / limit as f64) * 100.0).min(255.0) as u8
        } else {
            0
        };
        (used, limit, pct)
    }
}

impl Drop for UsageTracker {
    fn drop(&mut self) {
        // Save on exit
        if self.dirty {
            self.save();
        }
    }
}
