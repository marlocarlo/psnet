//! Network adapter enumeration using Win32 GetAdaptersInfo.
//!
//! Discovers ALL network interfaces: Ethernet, WiFi, VPN tunnels,
//! Docker vEthernet, WSL vEthernet, Hyper-V switches, etc.

use std::net::Ipv4Addr;

// ─── Win32 FFI ───────────────────────────────────────────────────────────────

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

#[link(name = "iphlpapi")]
extern "system" {
    fn GetAdaptersInfo(pAdapterInfo: *mut u8, pOutBufLen: *mut u32) -> u32;
}

const ERROR_SUCCESS: u32 = 0;
const ERROR_BUFFER_OVERFLOW: u32 = 111;

// ─── Adapter type constants ──────────────────────────────────────────────────

pub const IF_TYPE_ETHERNET: u32 = 6;
pub const IF_TYPE_PPP: u32 = 23;
pub const IF_TYPE_LOOPBACK: u32 = 24;
pub const IF_TYPE_SLIP: u32 = 28;
pub const IF_TYPE_WIFI: u32 = 71;
pub const IF_TYPE_TUNNEL: u32 = 131;

// ─── Public types ────────────────────────────────────────────────────────────

/// Information about a single network adapter.
#[derive(Clone, Debug)]
pub struct AdapterInfo {
    /// Internal adapter name (GUID).
    pub name: String,
    /// Human-readable description (e.g., "Intel(R) Wi-Fi 6 AX201").
    pub description: String,
    /// IPv4 address assigned to this adapter.
    pub ip: Ipv4Addr,
    /// Subnet mask.
    pub mask: Ipv4Addr,
    /// Default gateway (if configured).
    pub gateway: Option<Ipv4Addr>,
    /// MAC address string (XX:XX:XX:XX:XX:XX).
    pub mac: String,
    /// MIB interface type (IF_TYPE_*).
    pub if_type: u32,
}

// ─── Public API ──────────────────────────────────────────────────────────────

/// Enumerate all network adapters with valid IPv4 addresses.
/// Returns every adapter, including virtual ones (Docker, WSL, VPN, Hyper-V).
pub fn enumerate_all() -> Vec<AdapterInfo> {
    let mut result = Vec::new();

    unsafe {
        let mut size: u32 = 0;
        let ret = GetAdaptersInfo(std::ptr::null_mut(), &mut size);
        if ret != ERROR_BUFFER_OVERFLOW || size == 0 {
            return result;
        }

        let mut buf = vec![0u8; size as usize];
        let ret = GetAdaptersInfo(buf.as_mut_ptr(), &mut size);
        if ret != ERROR_SUCCESS {
            return result;
        }

        let mut adapter = buf.as_ptr() as *const IP_ADAPTER_INFO;
        while !adapter.is_null() {
            let ip_str = cstr_from_bytes(&(*adapter).IpAddressList.IpAddress);
            let mask_str = cstr_from_bytes(&(*adapter).IpAddressList.IpMask);
            let gw_str = cstr_from_bytes(&(*adapter).GatewayList.IpAddress);
            let desc = cstr_from_bytes(&(*adapter).Description);
            let name = cstr_from_bytes(&(*adapter).AdapterName);

            if let (Ok(ip), Ok(mask)) = (ip_str.parse::<Ipv4Addr>(), mask_str.parse::<Ipv4Addr>()) {
                if !ip.is_unspecified() && mask != Ipv4Addr::UNSPECIFIED {
                    let gw = gw_str.parse::<Ipv4Addr>().ok()
                        .filter(|g| !g.is_unspecified());

                    let addr_len = (*adapter).AddressLength as usize;
                    let mac = if addr_len >= 6 {
                        format!("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                            (*adapter).Address[0], (*adapter).Address[1], (*adapter).Address[2],
                            (*adapter).Address[3], (*adapter).Address[4], (*adapter).Address[5])
                    } else {
                        String::new()
                    };

                    result.push(AdapterInfo {
                        name,
                        description: desc,
                        ip,
                        mask,
                        gateway: gw,
                        mac,
                        if_type: (*adapter).Type,
                    });
                }
            }

            adapter = (*adapter).Next;
        }
    }

    result
}

fn cstr_from_bytes(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).to_string()
}
