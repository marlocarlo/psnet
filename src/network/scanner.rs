//! LAN device scanner using ARP (SendARP from iphlpapi.dll).
//!
//! Scans the local subnet to discover devices, their MAC addresses,
//! and tracks online/offline status over time. Runs scans on a background
//! thread to avoid blocking the UI tick.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;

use chrono::Local;

use crate::types::LanDevice;

// ─── Win32 FFI ───────────────────────────────────────────────────────────────

#[link(name = "iphlpapi")]
extern "system" {
    fn SendARP(
        DestIP: u32,
        SrcIP: u32,
        pMacAddr: *mut u8,
        PhyAddrLen: *mut u32,
    ) -> u32;

    fn GetAdaptersInfo(
        pAdapterInfo: *mut u8,
        pOutBufLen: *mut u32,
    ) -> u32;
}

const ERROR_SUCCESS: u32 = 0;
const ERROR_BUFFER_OVERFLOW: u32 = 111;

// ─── Adapter info parsing (simplified) ──────────────────────────────────────

#[repr(C)]
#[allow(non_snake_case, non_camel_case_types)]
struct IP_ADAPTER_INFO {
    Next: *mut IP_ADAPTER_INFO,
    ComboIndex: u32,
    AdapterName: [u8; 260],
    Description: [u8; 132],
    AddressLength: u32,
    Address: [u8; 8],
    Index: u32,
    Type: u32,
    DhcpEnabled: u32,
    CurrentIpAddress: *mut IP_ADDR_STRING,
    IpAddressList: IP_ADDR_STRING,
    GatewayList: IP_ADDR_STRING,
    DhcpServer: IP_ADDR_STRING,
    HaveWins: i32,
    PrimaryWinsServer: IP_ADDR_STRING,
    SecondaryWinsServer: IP_ADDR_STRING,
    LeaseObtained: i64,
    LeaseExpires: i64,
}

#[repr(C)]
#[allow(non_snake_case, non_camel_case_types)]
struct IP_ADDR_STRING {
    Next: *mut IP_ADDR_STRING,
    IpAddress: [u8; 16],
    IpMask: [u8; 16],
    Context: u32,
}

/// Get the local IPv4 address and subnet mask of the primary adapter.
fn get_local_subnet() -> Option<(Ipv4Addr, Ipv4Addr, Ipv4Addr)> {
    unsafe {
        let mut size: u32 = 0;
        let ret = GetAdaptersInfo(std::ptr::null_mut(), &mut size);
        if ret != ERROR_BUFFER_OVERFLOW || size == 0 {
            return None;
        }

        let mut buf = vec![0u8; size as usize];
        let ret = GetAdaptersInfo(buf.as_mut_ptr(), &mut size);
        if ret != ERROR_SUCCESS {
            return None;
        }

        let mut adapter = buf.as_ptr() as *const IP_ADAPTER_INFO;
        let mut best: Option<(Ipv4Addr, Ipv4Addr, Ipv4Addr)> = None;

        while !adapter.is_null() {
            let ip_str = cstr_from_bytes(&(*adapter).IpAddressList.IpAddress);
            let mask_str = cstr_from_bytes(&(*adapter).IpAddressList.IpMask);
            let gw_str = cstr_from_bytes(&(*adapter).GatewayList.IpAddress);

            if let (Ok(ip), Ok(mask)) = (ip_str.parse::<Ipv4Addr>(), mask_str.parse::<Ipv4Addr>()) {
                if !ip.is_loopback() && !ip.is_unspecified() && mask != Ipv4Addr::UNSPECIFIED {
                    let gw = gw_str.parse::<Ipv4Addr>().unwrap_or(Ipv4Addr::UNSPECIFIED);
                    if best.is_none() || !gw.is_unspecified() {
                        best = Some((ip, mask, gw));
                    }
                }
            }

            adapter = (*adapter).Next;
        }

        best
    }
}

fn cstr_from_bytes(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).to_string()
}

/// Generate all IPs in a subnet given IP and mask.
fn subnet_ips(ip: Ipv4Addr, mask: Ipv4Addr) -> Vec<Ipv4Addr> {
    let ip_u32 = u32::from(ip);
    let mask_u32 = u32::from(mask);
    let network = ip_u32 & mask_u32;
    let broadcast = network | !mask_u32;
    let host_count = broadcast - network;

    // Limit scan to /24 or smaller to avoid huge scans
    if host_count > 254 {
        // Fall back to /24 around the host IP
        let base = ip_u32 & 0xFFFFFF00;
        return (1..255)
            .map(|i| Ipv4Addr::from(base + i))
            .filter(|&a| a != ip)
            .collect();
    }

    (network + 1..broadcast)
        .map(Ipv4Addr::from)
        .filter(|&a| a != ip)
        .collect()
}

/// ARP-resolve a single IP. Returns MAC string if reachable.
fn arp_resolve(target_ip: Ipv4Addr) -> Option<String> {
    let dest = u32::from(target_ip).to_be();
    let mut mac_buf = [0u8; 6];
    let mut mac_len: u32 = 6;

    let ret = unsafe {
        SendARP(
            dest,
            0, // source IP = default
            mac_buf.as_mut_ptr(),
            &mut mac_len,
        )
    };

    if ret == ERROR_SUCCESS && mac_len >= 6 {
        Some(format!(
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            mac_buf[0], mac_buf[1], mac_buf[2],
            mac_buf[3], mac_buf[4], mac_buf[5]
        ))
    } else {
        None
    }
}

// ─── Scanner state ───────────────────────────────────────────────────────────

pub struct NetworkScanner {
    /// Known devices by MAC address (authoritative map).
    pub devices: Vec<LanDevice>,
    /// Shared result buffer from background scan thread.
    scan_result: Arc<Mutex<Option<Vec<(Ipv4Addr, String)>>>>,
    /// Whether a scan is in progress.
    scanning: Arc<Mutex<bool>>,
    /// Last scan timestamp.
    pub last_scan: Option<Instant>,
    /// Local subnet info.
    pub local_ip: Option<Ipv4Addr>,
    pub gateway: Option<Ipv4Addr>,
    pub subnet_mask: Option<Ipv4Addr>,
    /// Scan interval tracking.
    scan_tick: u32,
    /// User-assigned labels: MAC → display name.
    pub custom_labels: HashMap<String, String>,
    /// Persistence path for labels.
    labels_path: PathBuf,
}

impl NetworkScanner {
    pub fn new() -> Self {
        let (local_ip, subnet_mask, gateway) = get_local_subnet()
            .map(|(ip, mask, gw)| (Some(ip), Some(mask), Some(gw)))
            .unwrap_or((None, None, None));

        Self {
            devices: Vec::new(),
            scan_result: Arc::new(Mutex::new(None)),
            scanning: Arc::new(Mutex::new(false)),
            last_scan: None,
            local_ip,
            gateway,
            subnet_mask,
            scan_tick: 0,
            custom_labels: {
                let path = Self::labels_path();
                Self::load_labels(&path)
            },
            labels_path: Self::labels_path(),
        }
    }

    /// Trigger a background ARP scan. Non-blocking.
    pub fn start_scan(&self) {
        if let Ok(mut scanning) = self.scanning.lock() {
            if *scanning {
                return; // Already scanning
            }
            *scanning = true;
        }

        let (ip, mask) = match (self.local_ip, self.subnet_mask) {
            (Some(ip), Some(mask)) => (ip, mask),
            _ => return,
        };

        let result = Arc::clone(&self.scan_result);
        let scanning = Arc::clone(&self.scanning);

        thread::spawn(move || {
            let targets = subnet_ips(ip, mask);
            let mut found = Vec::new();

            for target in targets {
                if let Some(mac) = arp_resolve(target) {
                    found.push((target, mac));
                }
            }

            if let Ok(mut r) = result.lock() {
                *r = Some(found);
            }
            if let Ok(mut s) = scanning.lock() {
                *s = false;
            }
        });
    }

    /// Check if background scan has completed and merge results.
    /// Called each tick. Returns previous device list if devices changed.
    pub fn poll_results(&mut self) -> Option<Vec<LanDevice>> {
        let new_data = if let Ok(mut r) = self.scan_result.lock() {
            r.take()
        } else {
            None
        };

        let Some(scan_results) = new_data else {
            return None;
        };

        self.last_scan = Some(Instant::now());
        let now = Local::now().time();

        let prev_devices = self.devices.clone();

        // Build new map — update existing, add new, mark offline
        let mut seen_macs: std::collections::HashSet<String> = std::collections::HashSet::new();

        for (ip, mac) in scan_results {
            seen_macs.insert(mac.clone());
            if let Some(existing) = self.devices.iter_mut().find(|d| d.mac == mac) {
                existing.ip = IpAddr::V4(ip);
                existing.last_seen = now;
                existing.is_online = true;
                existing.custom_name = self.custom_labels.get(&mac).cloned();
            } else {
                self.devices.push(LanDevice {
                    ip: IpAddr::V4(ip),
                    mac: mac.clone(),
                    hostname: None,
                    vendor: mac_vendor_prefix(&mac),
                    first_seen: now,
                    last_seen: now,
                    is_online: true,
                    custom_name: self.custom_labels.get(&mac).cloned(),
                });
            }
        }

        // Mark unseen devices as offline
        for device in &mut self.devices {
            if !seen_macs.contains(&device.mac) {
                device.is_online = false;
            }
        }

        Some(prev_devices)
    }

    /// Called each tick. Auto-triggers scan every N ticks.
    pub fn tick(&mut self) {
        self.scan_tick += 1;
        // Scan every 30 ticks (~30 seconds)
        if self.scan_tick % 30 == 1 {
            self.start_scan();
        }
    }

    /// Is a scan currently in progress?
    pub fn is_scanning(&self) -> bool {
        self.scanning.lock().map(|s| *s).unwrap_or(false)
    }

    fn labels_path() -> PathBuf {
        if let Some(data_dir) = dirs::data_dir() {
            let dir = data_dir.join("psnet");
            let _ = std::fs::create_dir_all(&dir);
            dir.join("device_labels.json")
        } else {
            PathBuf::from("psnet_device_labels.json")
        }
    }

    fn load_labels(path: &PathBuf) -> HashMap<String, String> {
        match std::fs::read_to_string(path) {
            Ok(content) => serde_json::from_str(&content).unwrap_or_default(),
            Err(_) => HashMap::new(),
        }
    }

    fn save_labels(&self) {
        if let Ok(json) = serde_json::to_string_pretty(&self.custom_labels) {
            let _ = std::fs::write(&self.labels_path, json);
        }
    }

    /// Set a custom label for a device (by MAC address).
    pub fn set_label(&mut self, mac: &str, label: String) {
        if label.is_empty() {
            self.custom_labels.remove(mac);
        } else {
            self.custom_labels.insert(mac.to_string(), label);
        }
        self.save_labels();
        // Apply immediately to in-memory devices
        for device in &mut self.devices {
            if device.mac == mac {
                device.custom_name = self.custom_labels.get(mac).cloned();
            }
        }
    }

    /// Online device count.
    pub fn online_count(&self) -> usize {
        self.devices.iter().filter(|d| d.is_online).count()
    }
}

// ─── MAC vendor lookup (common prefixes) ────────────────────────────────────

fn mac_vendor_prefix(mac: &str) -> Option<String> {
    let prefix = mac.get(..8)?.to_uppercase();
    let vendor = match prefix.as_str() {
        "00:50:56" | "00:0C:29" => "VMware",
        "08:00:27" => "VirtualBox",
        "DC:A6:32" | "B8:27:EB" | "E4:5F:01" => "Raspberry Pi",
        "00:1A:79" | "78:7B:8A" => "Apple",
        "3C:22:FB" | "A4:83:E7" | "F8:75:A4" => "Apple",
        "F0:18:98" | "70:56:81" | "50:ED:3C" => "Apple",
        "00:15:5D" => "Hyper-V",
        "00:03:FF" | "00:04:5A" => "HP",
        "00:1B:63" | "00:24:36" | "28:6E:D4" => "Dell",
        "00:1C:BF" | "44:39:C4" | "E4:F0:04" => "Intel",
        "00:25:00" | "AC:22:0B" | "08:62:66" => "Apple",
        "B4:2E:99" | "00:1E:C2" | "00:0E:C6" => "Samsung",
        "48:5D:36" | "34:C9:F0" | "44:D9:E7" => "Google",
        "FC:F5:28" | "60:57:18" => "ZTE",
        "00:18:0A" | "00:1D:AA" => "D-Link",
        "00:14:6C" | "00:0C:43" | "20:CF:30" => "Netgear",
        "00:23:69" | "14:CC:20" | "E8:94:F6" => "Cisco",
        "00:1F:1F" | "B0:95:75" | "00:E0:67" => "Linksys",
        "00:24:01" | "C8:3A:35" | "60:A4:4C" => "TP-Link",
        _ => return None,
    };
    Some(vendor.to_string())
}
