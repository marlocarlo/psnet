//! Other Networks scanner — discovers devices on VPNs, Docker, WSL,
//! Hyper-V, Bluetooth, Mesh VPNs, Hotspots, Tunnels, secondary adapters,
//! and any non-primary network interface.
//!
//! **Progressive streaming architecture**: each discovery source runs
//! independently and pushes partial results as soon as it finds something.
//! The UI updates each tick with whatever has been found so far.
//!
//! **Instant first-pass**: ARP cache + adapter enumeration runs synchronously
//! before spawning slow sources, so the UI shows neighbors immediately.
//!
//! Architecture:
//!   adapters.rs   — Win32 FFI adapter enumeration + categorization
//!   bluetooth.rs  — Bluetooth PAN device discovery
//!   docker.rs     — Docker Engine API + CLI container/network deep discovery
//!   hotspot.rs    — Windows Mobile Hotspot + USB tethering
//!   hyperv.rs     — Hyper-V VM discovery via PowerShell
//!   meshvpn.rs    — Tailscale, ZeroTier, Nebula mesh VPN discovery
//!   tunnel.rs     — SSH tunnels, SOCKS proxies, ngrok/cloudflared
//!   vpn.rs        — VPN route table analysis + ICMP/TCP sweep
//!   wsl.rs        — WSL CLI instance discovery
//!   probes.rs     — 10 parallel probe methods (ARP, ICMP, TCP, NetBIOS, mDNS, etc.)
//!   mod.rs        — NetworksScanner orchestrator with progressive streaming (this file)

pub mod adapters;
pub mod bluetooth;
pub mod docker;
pub mod hotspot;
pub mod hyperv;
pub mod meshvpn;
pub mod probes;
pub mod tunnel;
pub mod vpn;
pub mod wsl;

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use chrono::{Local, NaiveTime};

use crate::types::{LanDevice, NetworkCategory, RemoteNetwork};

// ─── Scanner ─────────────────────────────────────────────────────────────────

/// Scanner for non-primary networks (VPN, Docker, WSL, secondary LAN, etc.).
///
/// Uses progressive streaming: each discovery source pushes results independently
/// via a shared `pending` buffer. `poll_results()` drains it each tick.
pub struct NetworksScanner {
    /// Discovered networks with their devices (merged, deduplicated).
    pub networks: Vec<RemoteNetwork>,
    /// Shared buffer where discovery threads push partial results.
    pending: Arc<Mutex<Vec<RemoteNetwork>>>,
    /// Number of active discovery threads (0 = scan complete).
    active_count: Arc<AtomicUsize>,
    /// Primary adapter IP (to exclude from results).
    pub primary_ip: Option<Ipv4Addr>,
    /// Tick counter for periodic rescans.
    scan_tick: u32,
    /// Whether initial scan has been triggered.
    initial_scan_done: bool,
}

impl NetworksScanner {
    pub fn new(primary_ip: Option<Ipv4Addr>) -> Self {
        Self {
            networks: Vec::new(),
            pending: Arc::new(Mutex::new(Vec::new())),
            active_count: Arc::new(AtomicUsize::new(0)),
            primary_ip,
            scan_tick: 0,
            initial_scan_done: false,
        }
    }

    /// Trigger a background scan. Each source runs independently and pushes
    /// results as it finds them. Does nothing if a scan is already in progress.
    pub fn start_scan(&self) {
        if self.active_count.load(Ordering::SeqCst) > 0 {
            return;
        }

        let primary_ip = self.primary_ip;

        // ── INSTANT FIRST-PASS ──────────────────────────────────────────
        // Read ARP cache + enumerate adapters synchronously BEFORE spawning
        // slow sources. This gives the UI something to display immediately.
        spawn_instant_sources(primary_ip, &self.pending, &self.active_count);

        // ── SLOW SOURCES (spawned in parallel) ──────────────────────────

        // Source 1: Docker — Engine API + CLI + Compose (fast, ~1-2s, has devices)
        spawn_source(&self.pending, &self.active_count, move || {
            discover_docker_networks()
        });

        // Source 2: WSL — CLI (fast, ~1s, has devices)
        spawn_source(&self.pending, &self.active_count, move || {
            discover_wsl_networks()
        });

        // Source 3: Hyper-V — PowerShell (medium, ~2s, has devices)
        spawn_source(&self.pending, &self.active_count, move || {
            hyperv::discover()
        });

        // Source 4: VPN — Route table + ICMP/TCP sweep (medium, ~2-4s, has devices)
        spawn_source(&self.pending, &self.active_count, move || {
            vpn::discover(primary_ip)
        });

        // Source 5: Adapter enumeration + deep probes per network (slowest, ~5-10s)
        // Adapter list appears immediately, then each network gets probed independently.
        spawn_adapter_probes(primary_ip, &self.pending, &self.active_count);

        // Source 6: Bluetooth PAN — PowerShell (medium, ~2s)
        spawn_source(&self.pending, &self.active_count, move || {
            bluetooth::discover()
        });

        // Source 7: Mesh VPNs — Tailscale, ZeroTier, Nebula (medium, ~1-3s)
        spawn_source(&self.pending, &self.active_count, move || {
            meshvpn::discover()
        });

        // Source 8: Hotspot — Mobile Hotspot + USB tethering (medium, ~1-2s)
        spawn_source(&self.pending, &self.active_count, move || {
            hotspot::discover()
        });

        // Source 9: Tunnels — SSH, SOCKS, ngrok, cloudflared (fast, ~1s)
        spawn_source(&self.pending, &self.active_count, move || {
            tunnel::discover()
        });
    }

    /// Poll for completed scan results. Drains pending buffer and merges
    /// incrementally into `self.networks`. Returns true if new data arrived.
    pub fn poll_results(&mut self) -> bool {
        let batch: Vec<RemoteNetwork> = {
            let mut lock = match self.pending.lock() {
                Ok(l) => l,
                Err(_) => return false,
            };
            std::mem::take(&mut *lock)
        };

        if batch.is_empty() {
            return false;
        }

        for incoming in batch {
            if let Some(existing) = self.networks.iter_mut().find(|n| n.name == incoming.name) {
                merge_into_network(existing, incoming);
            } else {
                self.networks.push(incoming);
            }
        }

        true
    }

    /// Called each tick. Triggers initial scan immediately, then rescans every 60s.
    pub fn tick(&mut self) {
        self.scan_tick += 1;

        // Trigger first scan immediately on tick 1
        if !self.initial_scan_done {
            self.initial_scan_done = true;
            self.start_scan();
        }

        // Auto-rescan every 30 seconds
        if self.scan_tick % 30 == 0 && self.scan_tick > 0 {
            self.start_scan();
        }
    }

    pub fn is_scanning(&self) -> bool {
        self.active_count.load(Ordering::SeqCst) > 0
    }

}

// ─── Spawn helpers ──────────────────────────────────────────────────────────

/// Spawn a single discovery source. Increments active_count on start,
/// decrements on finish. Pushes results to pending buffer.
fn spawn_source(
    pending: &Arc<Mutex<Vec<RemoteNetwork>>>,
    active: &Arc<AtomicUsize>,
    f: impl FnOnce() -> Vec<RemoteNetwork> + Send + 'static,
) {
    active.fetch_add(1, Ordering::SeqCst);
    let p = Arc::clone(pending);
    let a = Arc::clone(active);
    thread::spawn(move || {
        let results = f();
        if !results.is_empty() {
            if let Ok(mut lock) = p.lock() {
                lock.extend(results);
            }
        }
        a.fetch_sub(1, Ordering::SeqCst);
    });
}

/// Spawn adapter enumeration followed by independent deep probes per network.
/// Adapter list appears in UI immediately. Probed devices stream in as each
/// network's scan completes.
fn spawn_adapter_probes(
    primary_ip: Option<Ipv4Addr>,
    pending: &Arc<Mutex<Vec<RemoteNetwork>>>,
    active: &Arc<AtomicUsize>,
) {
    active.fetch_add(1, Ordering::SeqCst);
    let p = Arc::clone(pending);
    let a = Arc::clone(active);

    thread::spawn(move || {
        // Phase 1: Discover adapter networks (fast, <100ms)
        let adapter_nets = discover_adapter_networks(primary_ip);

        // Push network structures immediately so UI shows them right away
        if !adapter_nets.is_empty() {
            if let Ok(mut lock) = p.lock() {
                lock.extend(adapter_nets.clone());
            }
        }
        a.fetch_sub(1, Ordering::SeqCst); // adapter enum done

        // Phase 2: Deep probe each empty network independently
        // Each network gets its own thread with all 10 probe methods
        for net in adapter_nets {
            if !net.devices.is_empty() {
                continue;
            }

            a.fetch_add(1, Ordering::SeqCst);
            let p2 = Arc::clone(&p);
            let a2 = Arc::clone(&a);

            thread::spawn(move || {
                let hosts = probes::deep_scan_subnet(net.local_ip, net.subnet_mask, net.gateway);

                if !hosts.is_empty() {
                    let now = Local::now().time();
                    let ips: Vec<Ipv4Addr> = hosts.iter().map(|h| h.ip).collect();
                    let resolved =
                        crate::network::hostnames::resolve_all(&ips, net.gateway, &std::collections::HashMap::new());
                    let devices = hosts_to_lan_devices(&hosts, &resolved, now);

                    if let Ok(mut lock) = p2.lock() {
                        lock.push(RemoteNetwork {
                            name: net.name,
                            category: net.category,
                            adapter_name: net.adapter_name,
                            local_ip: net.local_ip,
                            subnet_mask: net.subnet_mask,
                            subnet_cidr: net.subnet_cidr,
                            gateway: net.gateway,
                            devices,
                        });
                    }
                }

                a2.fetch_sub(1, Ordering::SeqCst);
            });
        }
    });
}

// ─── Instant first-pass (ARP cache + adapters) ──────────────────────────────

/// Spawn a thread that immediately reads the OS ARP cache and adapter list,
/// groups ARP entries by interface, and pushes results to pending.
/// This completes in <10ms on any machine and gives the UI instant data.
fn spawn_instant_sources(
    primary_ip: Option<Ipv4Addr>,
    pending: &Arc<Mutex<Vec<RemoteNetwork>>>,
    active: &Arc<AtomicUsize>,
) {
    active.fetch_add(1, Ordering::SeqCst);
    let p = Arc::clone(pending);
    let a = Arc::clone(active);

    thread::spawn(move || {
        let now = Local::now().time();

        // Step 1: Read all ARP cache entries (instant, zero network traffic)
        let arp_entries = probes::arp_cache_read_all();

        // Step 2: Enumerate adapters (instant Win32 API call)
        let all_adapters = adapters::enumerate_all();

        if arp_entries.is_empty() {
            a.fetch_sub(1, Ordering::SeqCst);
            return;
        }

        // Step 3: Group ARP entries by interface index
        let mut by_iface: HashMap<u32, Vec<&probes::ArpCacheEntry>> = HashMap::new();
        for entry in &arp_entries {
            // Skip entries matching primary IP's subnet (those belong to main LAN scanner)
            if let Some(pip) = primary_ip {
                let pip_prefix = u32::from(pip) & 0xFFFFFF00;
                let entry_prefix = u32::from(entry.ip) & 0xFFFFFF00;
                if pip_prefix == entry_prefix {
                    continue;
                }
            }
            by_iface.entry(entry.if_index).or_default().push(entry);
        }

        // Step 4: Match each group to a discovered adapter
        let mut networks = Vec::new();

        for (if_index, entries) in &by_iface {
            // Find the adapter for this interface index
            // Note: GetAdaptersInfo uses a different index than GetIpNetTable in some cases.
            // Try matching by subnet overlap.
            let adapter = all_adapters.iter().find(|a| {
                if primary_ip.map(|p| p == a.ip).unwrap_or(false) {
                    return false;
                }
                // Check if any ARP entry falls in this adapter's subnet
                let net = u32::from(a.ip) & u32::from(a.mask);
                entries.iter().any(|e| {
                    (u32::from(e.ip) & u32::from(a.mask)) == net
                })
            });

            let (net_name, category, local_ip, subnet_mask, adapter_name) = if let Some(a) = adapter {
                let cat = categorize_adapter(a);
                (a.description.clone(), cat, a.ip, a.mask, a.name.clone())
            } else {
                // Unknown interface — label with index
                (
                    format!("Interface #{}", if_index),
                    NetworkCategory::Secondary,
                    Ipv4Addr::UNSPECIFIED,
                    Ipv4Addr::new(255, 255, 255, 0),
                    format!("if{}", if_index),
                )
            };

            // Skip if we'd create a network with unspecified IP and no entries
            if local_ip.is_unspecified() && entries.is_empty() {
                continue;
            }

            let cidr = u32::from(subnet_mask).count_ones();
            let net_addr = u32::from(local_ip) & u32::from(subnet_mask);
            let subnet_cidr = format!("{}/{}", Ipv4Addr::from(net_addr), cidr);

            let devices: Vec<LanDevice> = entries
                .iter()
                .filter(|e| e.ip != local_ip)
                .map(|e| {
                    let mac = e.mac.clone().unwrap_or_default();
                    let vendor = if !mac.is_empty() {
                        crate::network::scanner::mac_vendor(&mac)
                    } else {
                        None
                    };
                    LanDevice {
                        ip: IpAddr::V4(e.ip),
                        mac,
                        hostname: None,
                        vendor,
                        first_seen: now,
                        last_seen: now,
                        is_online: true,
                        custom_name: None,
                        discovery_info: "ARP-Cache (instant)".to_string(),
                        open_ports: String::new(),
                        bytes_sent: 0,
                        bytes_received: 0,
                        tick_sent: 0,
                        tick_received: 0,
                        speed_sent: 0.0,
                        speed_received: 0.0,
                    }
                })
                .collect();

            if devices.is_empty() {
                continue;
            }

            networks.push(RemoteNetwork {
                name: net_name,
                category,
                adapter_name,
                local_ip,
                subnet_mask,
                subnet_cidr,
                gateway: adapter.and_then(|a| a.gateway),
                devices,
            });
        }

        if !networks.is_empty() {
            if let Ok(mut lock) = p.lock() {
                lock.extend(networks);
            }
        }

        a.fetch_sub(1, Ordering::SeqCst);
    });
}

// ─── Merge logic ─────────────────────────────────────────────────────────────

/// Merge incoming network data into an existing network. Deduplicates by IP,
/// enriches existing devices with new info.
fn merge_into_network(existing: &mut RemoteNetwork, incoming: RemoteNetwork) {
    // Update network-level metadata if missing
    if existing.gateway.is_none() && incoming.gateway.is_some() {
        existing.gateway = incoming.gateway;
    }
    if existing.subnet_cidr.is_empty() && !incoming.subnet_cidr.is_empty() {
        existing.subnet_cidr = incoming.subnet_cidr;
    }

    // Merge devices
    for dev in incoming.devices {
        if let Some(ex_dev) = existing.devices.iter_mut().find(|d| d.ip == dev.ip) {
            // Enrich existing device with new info
            if ex_dev.mac.is_empty() && !dev.mac.is_empty() {
                ex_dev.mac = dev.mac;
            }
            if ex_dev.hostname.is_none() && dev.hostname.is_some() {
                ex_dev.hostname = dev.hostname;
            }
            if ex_dev.vendor.is_none() && dev.vendor.is_some() {
                ex_dev.vendor = dev.vendor;
            }
            if !dev.discovery_info.is_empty()
                && !ex_dev.discovery_info.contains(&dev.discovery_info)
            {
                if !ex_dev.discovery_info.is_empty() {
                    ex_dev.discovery_info.push_str("  ");
                }
                ex_dev.discovery_info.push_str(&dev.discovery_info);
            }
            if ex_dev.open_ports.is_empty() && !dev.open_ports.is_empty() {
                ex_dev.open_ports = dev.open_ports;
            }
            ex_dev.last_seen = dev.last_seen;
            ex_dev.is_online = true;
        } else {
            // Entirely new device
            existing.devices.push(dev);
        }
    }
}

/// Convert probes::MergedHost results + hostname resolutions into LanDevices.
fn hosts_to_lan_devices(
    hosts: &[probes::MergedHost],
    resolved: &HashMap<Ipv4Addr, crate::network::hostnames::ResolvedDevice>,
    now: NaiveTime,
) -> Vec<LanDevice> {
    let mut devices = Vec::new();

    for host in hosts {
        let hostname = host.hostname.clone().or_else(|| {
            resolved
                .get(&host.ip)
                .map(|r| r.hostname.clone())
                .filter(|h| !h.is_empty())
        });

        let discovery_info = {
            let mut info = format!("Probes:{}", host.methods.join(","));
            if let Some(r) = resolved.get(&host.ip) {
                if !r.details.is_empty() {
                    info.push_str(&format!("  {}", r.details));
                }
            }
            info
        };

        let open_ports = resolved
            .get(&host.ip)
            .map(|r| crate::network::hostnames::format_ports(&r.open_ports))
            .unwrap_or_default();

        let mac = host.mac.clone().unwrap_or_default();
        let vendor = if !mac.is_empty() {
            crate::network::scanner::mac_vendor(&mac)
        } else {
            None
        };

        devices.push(LanDevice {
            ip: IpAddr::V4(host.ip),
            mac,
            hostname,
            vendor,
            first_seen: now,
            last_seen: now,
            is_online: true,
            custom_name: None,
            discovery_info,
            open_ports,
            bytes_sent: 0,
            bytes_received: 0,
            tick_sent: 0,
            tick_received: 0,
            speed_sent: 0.0,
            speed_received: 0.0,
        });
    }

    devices
}

// ─── Adapter-based network discovery ─────────────────────────────────────────

fn categorize_adapter(adapter: &adapters::AdapterInfo) -> NetworkCategory {
    let desc_lower = adapter.description.to_lowercase();

    // Bluetooth PAN
    if desc_lower.contains("bluetooth")
        || desc_lower.contains("bt network")
        || desc_lower.contains("bnep")
    {
        return NetworkCategory::Bluetooth;
    }
    // Mesh VPNs (before generic VPN check)
    if desc_lower.contains("tailscale")
        || desc_lower.contains("zerotier")
        || desc_lower.contains("nebula")
    {
        return NetworkCategory::MeshVpn;
    }
    // Hotspot / tethering
    if desc_lower.contains("wi-fi direct")
        || desc_lower.contains("hosted network")
        || desc_lower.contains("mobile hotspot")
        || desc_lower.contains("rndis")
        || desc_lower.contains("cdc ethernet")
        || desc_lower.contains("usb ethernet")
        || desc_lower.contains("android")
        || desc_lower.contains("iphone")
    {
        return NetworkCategory::Hotspot;
    }
    // Traditional VPNs
    if adapter.if_type == adapters::IF_TYPE_TUNNEL
        || adapter.if_type == adapters::IF_TYPE_PPP
        || desc_lower.contains("tap")
        || desc_lower.contains("tun ")
        || desc_lower.contains("vpn")
        || desc_lower.contains("wireguard")
        || desc_lower.contains("openvpn")
        || desc_lower.contains("cisco")
        || desc_lower.contains("fortinet")
        || desc_lower.contains("forticlient")
        || desc_lower.contains("juniper")
        || desc_lower.contains("globalprotect")
        || desc_lower.contains("nordlynx")
        || desc_lower.contains("proton")
        || desc_lower.contains("mullvad")
        || desc_lower.contains("surfshark")
        || desc_lower.contains("wintun")
    {
        return NetworkCategory::Vpn;
    }
    if desc_lower.contains("wsl") {
        return NetworkCategory::Wsl;
    }
    if desc_lower.contains("docker") {
        return NetworkCategory::Docker;
    }
    if desc_lower.contains("hyper-v") || desc_lower.contains("vethernet") {
        return NetworkCategory::HyperV;
    }
    if desc_lower.contains("vmware")
        || desc_lower.contains("virtualbox")
        || desc_lower.contains("virtual")
    {
        return NetworkCategory::Virtual;
    }

    NetworkCategory::Secondary
}

fn discover_adapter_networks(primary_ip: Option<Ipv4Addr>) -> Vec<RemoteNetwork> {
    let all_adapters = adapters::enumerate_all();
    let mut networks = Vec::new();

    for adapter in &all_adapters {
        if primary_ip.map(|p| p == adapter.ip).unwrap_or(false) {
            continue;
        }
        if adapter.if_type == adapters::IF_TYPE_LOOPBACK
            || adapter.if_type == adapters::IF_TYPE_SLIP
            || adapter.ip.is_loopback()
        {
            continue;
        }
        let octets = adapter.ip.octets();
        if octets[0] == 169 && octets[1] == 254 {
            continue;
        }

        let category = categorize_adapter(adapter);
        let cidr = u32::from(adapter.mask).count_ones();
        let net_addr = u32::from(adapter.ip) & u32::from(adapter.mask);
        let subnet_cidr = format!("{}/{}", Ipv4Addr::from(net_addr), cidr);

        networks.push(RemoteNetwork {
            name: adapter.description.clone(),
            category,
            adapter_name: adapter.name.clone(),
            local_ip: adapter.ip,
            subnet_mask: adapter.mask,
            subnet_cidr,
            gateway: adapter.gateway,
            devices: Vec::new(),
        });
    }

    networks
}

// ─── Docker network discovery (deep) ─────────────────────────────────────────

fn discover_docker_networks() -> Vec<RemoteNetwork> {
    let docker_nets = docker::discover_deep();
    if docker_nets.is_empty() {
        return Vec::new();
    }

    let now = Local::now().time();
    let mut networks = Vec::new();

    for dnet in docker_nets {
        let mut devices = Vec::new();

        for c in &dnet.containers {
            if let Some(ip) = c.ip {
                let status_str = if c.status.is_empty() {
                    "connected".to_string()
                } else {
                    c.status.clone()
                };
                let image_str = if c.image.is_empty() {
                    String::new()
                } else {
                    c.image.clone()
                };

                devices.push(LanDevice {
                    ip: IpAddr::V4(ip),
                    mac: c.mac.clone(),
                    hostname: Some(c.name.clone()),
                    vendor: if image_str.is_empty() {
                        Some("Docker Container".to_string())
                    } else {
                        Some(format!("Docker: {}", image_str))
                    },
                    first_seen: now,
                    last_seen: now,
                    is_online: status_str.to_lowercase().contains("up"),
                    custom_name: None,
                    discovery_info: format!(
                        "Image:{}  Status:{}  Network:{}  Driver:{}",
                        image_str, status_str, dnet.name, dnet.driver
                    ),
                    open_ports: c.ports.clone(),
                    bytes_sent: 0,
                    bytes_received: 0,
                    tick_sent: 0,
                    tick_received: 0,
                    speed_sent: 0.0,
                    speed_received: 0.0,
                });
            }
        }

        if devices.is_empty() {
            continue;
        }

        let gateway = dnet.gateway;
        let local_ip = gateway.unwrap_or(Ipv4Addr::new(172, 17, 0, 1));

        let (subnet_cidr, subnet_mask) = if let Some(ref sub) = dnet.subnet {
            parse_cidr(sub).unwrap_or_else(|| {
                let net_u32 = u32::from(local_ip) & 0xFFFF0000;
                (
                    format!("{}/16", Ipv4Addr::from(net_u32)),
                    Ipv4Addr::new(255, 255, 0, 0),
                )
            })
        } else {
            let net_u32 = u32::from(local_ip) & 0xFFFF0000;
            (
                format!("{}/16", Ipv4Addr::from(net_u32)),
                Ipv4Addr::new(255, 255, 0, 0),
            )
        };

        networks.push(RemoteNetwork {
            name: format!("Docker: {} ({})", dnet.name, dnet.driver),
            category: NetworkCategory::Docker,
            adapter_name: String::new(),
            local_ip,
            subnet_mask,
            subnet_cidr,
            gateway,
            devices,
        });
    }

    networks
}

// ─── WSL network discovery ───────────────────────────────────────────────────

fn discover_wsl_networks() -> Vec<RemoteNetwork> {
    let instances = wsl::discover();
    if instances.is_empty() {
        return Vec::new();
    }

    let now = Local::now().time();
    let mut devices = Vec::new();
    let mut first_ip: Option<Ipv4Addr> = None;

    for inst in &instances {
        // Build version tag: "WSL2" / "WSL1" / "WSL"
        let ver_tag = match inst.wsl_version {
            1 => "WSL1",
            2 => "WSL2",
            _ => "WSL",
        };

        // Build vendor string with OS info
        let vendor = if !inst.os_pretty_name.is_empty() {
            format!("{} ({})", ver_tag, inst.os_pretty_name)
        } else {
            format!("{} Instance", ver_tag)
        };

        // Build hostname: prefer Linux hostname, fall back to distro name
        let hostname = if !inst.linux_hostname.is_empty() && inst.linux_hostname != inst.name {
            format!("{} ({})", inst.name, inst.linux_hostname)
        } else {
            inst.name.clone()
        };

        // Build rich discovery_info
        let mut info_parts: Vec<String> = vec![format!("WSL:{}", inst.name)];
        if inst.wsl_version > 0 {
            info_parts.push(format!("VER:{}", inst.wsl_version));
        }
        if inst.is_default {
            info_parts.push("DEFAULT".to_string());
        }
        if !inst.os_id.is_empty() {
            info_parts.push(format!("OS:{}", inst.os_id));
        }
        if !inst.os_version.is_empty() {
            info_parts.push(format!("OSVER:{}", inst.os_version));
        }
        if !inst.kernel.is_empty() {
            info_parts.push(format!("KERN:{}", inst.kernel));
        }
        if inst.all_ips.len() > 1 {
            let extra: Vec<String> = inst.all_ips.iter().skip(1).map(|ip| ip.to_string()).collect();
            info_parts.push(format!("IPs:{}", extra.join(",")));
        }

        // Use first available IP
        let ip = inst.ip.or_else(|| inst.all_ips.first().copied());

        if let Some(ip) = ip {
            if first_ip.is_none() {
                first_ip = Some(ip);
            }
            devices.push(LanDevice {
                ip: IpAddr::V4(ip),
                mac: inst.mac.clone(),
                hostname: Some(hostname),
                vendor: Some(vendor),
                first_seen: now,
                last_seen: now,
                is_online: inst.is_running,
                custom_name: None,
                discovery_info: info_parts.join("  "),
                open_ports: String::new(),
                bytes_sent: 0,
                bytes_received: 0,
                tick_sent: 0,
                tick_received: 0,
                speed_sent: 0.0,
                speed_received: 0.0,
            });
        } else if !inst.is_running {
            // Include stopped instances with no IP so user sees them
            devices.push(LanDevice {
                ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                mac: String::new(),
                hostname: Some(hostname),
                vendor: Some(vendor),
                first_seen: now,
                last_seen: now,
                is_online: false,
                custom_name: None,
                discovery_info: info_parts.join("  "),
                open_ports: String::new(),
                bytes_sent: 0,
                bytes_received: 0,
                tick_sent: 0,
                tick_received: 0,
                speed_sent: 0.0,
                speed_received: 0.0,
            });
        }
    }

    if devices.is_empty() {
        return Vec::new();
    }

    // Derive network address from first discovered IP instead of hardcoding
    let (local_ip, subnet_mask, cidr) = if let Some(ip) = first_ip {
        let octets = ip.octets();
        // WSL2 typically uses 172.x.x.x/20 or similar
        let net = Ipv4Addr::new(octets[0], octets[1], octets[2] & 0xF0, 0);
        let mask = Ipv4Addr::new(255, 255, 240, 0);
        let cidr = format!("{}/20", net);
        (ip, mask, cidr)
    } else {
        (Ipv4Addr::new(172, 28, 0, 1), Ipv4Addr::new(255, 240, 0, 0), "172.16.0.0/12".to_string())
    };

    vec![RemoteNetwork {
        name: "WSL".to_string(),
        category: NetworkCategory::Wsl,
        adapter_name: String::new(),
        local_ip,
        subnet_mask,
        subnet_cidr: cidr,
        gateway: None,
        devices,
    }]
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Generate all host IPs in a subnet (max 254 for large subnets).
pub(crate) fn subnet_ips(ip: Ipv4Addr, mask: Ipv4Addr) -> Vec<Ipv4Addr> {
    let ip_u32 = u32::from(ip);
    let mask_u32 = u32::from(mask);
    let network = ip_u32 & mask_u32;
    let broadcast = network | !mask_u32;
    let host_count = broadcast - network;

    if host_count > 254 {
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

/// Parse a CIDR string like "172.17.0.0/16" into (cidr_string, mask).
fn parse_cidr(cidr: &str) -> Option<(String, Ipv4Addr)> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return None;
    }
    let _ip: Ipv4Addr = parts[0].parse().ok()?;
    let prefix: u32 = parts[1].parse().ok()?;
    if prefix > 32 {
        return None;
    }
    let mask = if prefix == 0 {
        0
    } else {
        !0u32 << (32 - prefix)
    };
    Some((cidr.to_string(), Ipv4Addr::from(mask)))
}
