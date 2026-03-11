//! Bluetooth PAN network discovery for Windows.
//!
//! Discovery methods:
//!   1. Get-NetAdapter — find Bluetooth network adapters
//!   2. Get-PnpDevice — find paired Bluetooth devices
//!
//! Returns Vec<RemoteNetwork> with category Bluetooth.

use std::net::{IpAddr, Ipv4Addr};
use std::process::Command;

use chrono::Local;

use crate::types::{LanDevice, NetworkCategory, RemoteNetwork};

#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;

#[cfg(target_os = "windows")]
const CREATE_NO_WINDOW: u32 = 0x08000000;

/// Create a PowerShell Command with CREATE_NO_WINDOW on Windows.
fn quiet_powershell() -> Command {
    let mut cmd = Command::new("powershell");
    #[cfg(target_os = "windows")]
    {
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    cmd.args(["-NoProfile", "-NonInteractive", "-Command"]);
    cmd
}

/// Discover Bluetooth PAN networks and paired devices.
pub fn discover() -> Vec<RemoteNetwork> {
    let now = Local::now().time();

    // Discover BT network adapters
    let adapters = discover_bt_adapters();

    // Discover paired BT devices
    let paired = discover_paired_devices();

    if adapters.is_empty() && paired.is_empty() {
        return Vec::new();
    }

    let mut devices = Vec::new();

    // Add paired BT devices as LanDevices
    for pd in &paired {
        devices.push(LanDevice {
            ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            mac: pd.mac.clone(),
            hostname: Some(pd.name.clone()),
            vendor: Some("Bluetooth Device".to_string()),
            first_seen: now,
            last_seen: now,
            is_online: pd.connected,
            custom_name: None,
            discovery_info: format!("BT:{} Class:{}", pd.status, pd.device_class),
            open_ports: String::new(),
            bytes_sent: 0,
            bytes_received: 0,
            tick_sent: 0,
            tick_received: 0,
            speed_sent: 0.0,
            speed_received: 0.0,
        });
    }

    // If we have a BT adapter with an IP, use it; otherwise use a placeholder
    let (local_ip, adapter_name) = if let Some(a) = adapters.first() {
        (a.ip.unwrap_or(Ipv4Addr::new(192, 168, 44, 1)), a.name.clone())
    } else {
        (Ipv4Addr::new(192, 168, 44, 1), "Bluetooth PAN".to_string())
    };

    if devices.is_empty() {
        return Vec::new();
    }

    vec![RemoteNetwork {
        name: "Bluetooth PAN".to_string(),
        category: NetworkCategory::Bluetooth,
        adapter_name,
        local_ip,
        subnet_mask: Ipv4Addr::new(255, 255, 255, 0),
        subnet_cidr: format!("{}/24", local_ip),
        gateway: None,
        devices,
    }]
}

struct BtAdapter {
    name: String,
    ip: Option<Ipv4Addr>,
}

struct PairedDevice {
    name: String,
    mac: String,
    status: String,
    device_class: String,
    connected: bool,
}

fn discover_bt_adapters() -> Vec<BtAdapter> {
    let output = quiet_powershell()
        .arg("Get-NetAdapter | Where-Object { $_.InterfaceDescription -like '*Bluetooth*' } | Select-Object Name,InterfaceDescription,Status,MacAddress | ConvertTo-Json -Compress")
        .output();

    let output = match output {
        Ok(o) if o.status.success() => o,
        _ => return Vec::new(),
    };

    let text = String::from_utf8_lossy(&output.stdout);
    let text = text.trim();
    if text.is_empty() {
        return Vec::new();
    }

    let mut adapters = Vec::new();

    // Could be a single object or array
    if let Ok(arr) = serde_json::from_str::<Vec<serde_json::Value>>(text) {
        for obj in &arr {
            if let Some(a) = parse_bt_adapter(obj) {
                adapters.push(a);
            }
        }
    } else if let Ok(obj) = serde_json::from_str::<serde_json::Value>(text) {
        if let Some(a) = parse_bt_adapter(&obj) {
            adapters.push(a);
        }
    }

    adapters
}

fn parse_bt_adapter(obj: &serde_json::Value) -> Option<BtAdapter> {
    let name = obj.get("Name")?.as_str()?.to_string();
    Some(BtAdapter { name, ip: None })
}

fn discover_paired_devices() -> Vec<PairedDevice> {
    let output = quiet_powershell()
        .arg("Get-PnpDevice -Class Bluetooth | Where-Object { $_.Status -eq 'OK' -and $_.FriendlyName -ne 'Bluetooth Device' -and $_.FriendlyName -notlike '*Radio*' } | Select-Object FriendlyName,Status,InstanceId,Class | ConvertTo-Json -Compress")
        .output();

    let output = match output {
        Ok(o) if o.status.success() => o,
        _ => return Vec::new(),
    };

    let text = String::from_utf8_lossy(&output.stdout);
    let text = text.trim();
    if text.is_empty() {
        return Vec::new();
    }

    let mut devices = Vec::new();

    if let Ok(arr) = serde_json::from_str::<Vec<serde_json::Value>>(text) {
        for obj in &arr {
            if let Some(d) = parse_paired_device(obj) {
                devices.push(d);
            }
        }
    } else if let Ok(obj) = serde_json::from_str::<serde_json::Value>(text) {
        if let Some(d) = parse_paired_device(&obj) {
            devices.push(d);
        }
    }

    devices
}

fn parse_paired_device(obj: &serde_json::Value) -> Option<PairedDevice> {
    let name = obj.get("FriendlyName")?.as_str()?.to_string();
    let status = obj.get("Status").and_then(|v| v.as_str()).unwrap_or("OK").to_string();

    // Extract MAC from InstanceId (format: BTHENUM\..._MACADDR)
    let instance_id = obj.get("InstanceId").and_then(|v| v.as_str()).unwrap_or("");
    let mac = extract_bt_mac(instance_id);

    let device_class = obj.get("Class").and_then(|v| v.as_str()).unwrap_or("Bluetooth").to_string();

    Some(PairedDevice {
        name,
        mac,
        status: status.clone(),
        device_class,
        connected: status == "OK",
    })
}

/// Extract MAC address from Bluetooth InstanceId.
/// Format: BTHENUM\{...}_AABBCCDDEEFF or BTHENUM\Dev_AABBCCDDEEFF...
fn extract_bt_mac(instance_id: &str) -> String {
    let upper = instance_id.to_uppercase();
    // Look for 12 hex chars pattern after common BT prefixes
    for part in upper.split(&['\\', '_', '&'][..]) {
        let hex_only: String = part.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        if hex_only.len() == 12 {
            return format!(
                "{}:{}:{}:{}:{}:{}",
                &hex_only[0..2], &hex_only[2..4], &hex_only[4..6],
                &hex_only[6..8], &hex_only[8..10], &hex_only[10..12]
            );
        }
    }
    String::new()
}
