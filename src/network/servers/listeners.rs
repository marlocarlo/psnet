//! Enumerates all listening TCP and UDP ports on the local machine using
//! Windows `GetExtendedTcpTable` / `GetExtendedUdpTable` APIs.
//!
//! Performance: uses `TCP_TABLE_OWNER_PID_LISTENER` class (value 3) which
//! returns ONLY listening sockets — much faster than `TCP_TABLE_OWNER_PID_ALL`.
//! Typical call completes in 1-5 ms.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use sysinfo::{Pid, ProcessesToUpdate, System};

use super::types::ListenProto;

// ─── Raw listener record ─────────────────────────────────────────────────────

/// A single listening socket discovered via the OS tables.
#[derive(Debug, Clone)]
pub struct RawListener {
    pub proto: ListenProto,
    pub bind_addr: IpAddr,
    pub port: u16,
    pub pid: u32,
}

// ─── Process info resolved via sysinfo ───────────────────────────────────────

/// Process metadata resolved from a PID.
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub name: String,
    pub exe_path: String,
    pub cmdline: String,
}

// ─── Windows FFI declarations ────────────────────────────────────────────────

#[link(name = "iphlpapi")]
extern "system" {
    fn GetExtendedTcpTable(
        pTcpTable: *mut u8,
        pdwSize: *mut u32,
        bOrder: i32,
        ulAf: u32,
        TableClass: u32,
        Reserved: u32,
    ) -> u32;

    fn GetExtendedUdpTable(
        pUdpTable: *mut u8,
        pdwSize: *mut u32,
        bOrder: i32,
        ulAf: u32,
        TableClass: u32,
        Reserved: u32,
    ) -> u32;
}

const AF_INET: u32 = 2;
const AF_INET6: u32 = 23;

/// TCP_TABLE_OWNER_PID_LISTENER — returns only LISTENING TCP rows.
const TCP_TABLE_OWNER_PID_LISTENER: u32 = 3;

/// UDP_TABLE_OWNER_PID — returns all UDP rows (UDP has no "listen" state).
const UDP_TABLE_OWNER_PID: u32 = 1;

const NO_ERROR: u32 = 0;

// ─── MIB structs (repr C, matching Windows layout) ───────────────────────────

#[repr(C)]
#[allow(non_snake_case, non_camel_case_types)]
struct MIB_TCPROW_OWNER_PID {
    dwState: u32,
    dwLocalAddr: u32,
    dwLocalPort: u32,
    dwRemoteAddr: u32,
    dwRemotePort: u32,
    dwOwningPid: u32,
}

#[repr(C)]
#[allow(non_snake_case, non_camel_case_types)]
struct MIB_TCPTABLE_OWNER_PID {
    dwNumEntries: u32,
    table: [MIB_TCPROW_OWNER_PID; 1],
}

#[repr(C)]
#[allow(non_snake_case, non_camel_case_types)]
struct MIB_TCP6ROW_OWNER_PID {
    ucLocalAddr: [u8; 16],
    dwLocalScopeId: u32,
    dwLocalPort: u32,
    ucRemoteAddr: [u8; 16],
    dwRemoteScopeId: u32,
    dwRemotePort: u32,
    dwState: u32,
    dwOwningPid: u32,
}

#[repr(C)]
#[allow(non_snake_case, non_camel_case_types)]
struct MIB_TCP6TABLE_OWNER_PID {
    dwNumEntries: u32,
    table: [MIB_TCP6ROW_OWNER_PID; 1],
}

#[repr(C)]
#[allow(non_snake_case, non_camel_case_types)]
struct MIB_UDPROW_OWNER_PID {
    dwLocalAddr: u32,
    dwLocalPort: u32,
    dwOwningPid: u32,
}

#[repr(C)]
#[allow(non_snake_case, non_camel_case_types)]
struct MIB_UDPTABLE_OWNER_PID {
    dwNumEntries: u32,
    table: [MIB_UDPROW_OWNER_PID; 1],
}

#[repr(C)]
#[allow(non_snake_case, non_camel_case_types)]
struct MIB_UDP6ROW_OWNER_PID {
    ucLocalAddr: [u8; 16],
    dwLocalScopeId: u32,
    dwLocalPort: u32,
    dwOwningPid: u32,
}

#[repr(C)]
#[allow(non_snake_case, non_camel_case_types)]
struct MIB_UDP6TABLE_OWNER_PID {
    dwNumEntries: u32,
    table: [MIB_UDP6ROW_OWNER_PID; 1],
}

// ─── Port byte-order conversion ──────────────────────────────────────────────

/// Convert a port value from network byte order (as stored in MIB tables)
/// to host byte order. The Windows API stores ports in a u32 where only the
/// lower 16 bits matter, but those 16 bits are in big-endian order.
#[inline]
fn port_from_raw(raw: u32) -> u16 {
    (((raw >> 8) & 0xFF) | ((raw & 0xFF) << 8)) as u16
}

// ─── Public API ──────────────────────────────────────────────────────────────

/// Enumerate all listening TCP and UDP ports. Fast (~1-5 ms).
pub fn enumerate_listeners() -> Vec<RawListener> {
    let mut result = Vec::new();
    enumerate_tcp4_listeners(&mut result);
    enumerate_tcp6_listeners(&mut result);
    enumerate_udp4_listeners(&mut result);
    enumerate_udp6_listeners(&mut result);
    result
}

/// Resolve process details for a set of PIDs.
/// Returns `HashMap<pid, ProcessInfo>` with name, exe path, and command line.
pub fn resolve_process_info(pids: &[u32]) -> HashMap<u32, ProcessInfo> {
    let mut map = HashMap::new();
    if pids.is_empty() {
        return map;
    }

    let mut sys = System::new();
    let sysinfo_pids: Vec<Pid> = pids.iter().map(|&p| Pid::from_u32(p)).collect();
    sys.refresh_processes(ProcessesToUpdate::Some(&sysinfo_pids), true);

    for &pid in pids {
        if let Some(proc) = sys.process(Pid::from_u32(pid)) {
            let name = proc.name().to_string_lossy().to_string();
            let exe_path = proc
                .exe()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default();
            let cmdline = proc.cmd().iter().map(|s| s.to_string_lossy()).collect::<Vec<_>>().join(" ");
            map.insert(pid, ProcessInfo {
                name,
                exe_path,
                cmdline,
            });
        }
    }

    map
}

// ─── TCP IPv4 listeners ──────────────────────────────────────────────────────

fn enumerate_tcp4_listeners(result: &mut Vec<RawListener>) {
    unsafe {
        let mut size: u32 = 0;
        GetExtendedTcpTable(
            std::ptr::null_mut(),
            &mut size,
            0,
            AF_INET,
            TCP_TABLE_OWNER_PID_LISTENER,
            0,
        );
        if size == 0 {
            return;
        }

        let mut buf = vec![0u8; size as usize];
        let ret = GetExtendedTcpTable(
            buf.as_mut_ptr(),
            &mut size,
            0,
            AF_INET,
            TCP_TABLE_OWNER_PID_LISTENER,
            0,
        );
        if ret != NO_ERROR {
            return;
        }

        let table = &*(buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
        let num = table.dwNumEntries as usize;
        if num == 0 {
            return;
        }
        let rows = std::slice::from_raw_parts(table.table.as_ptr(), num);

        for row in rows {
            result.push(RawListener {
                proto: ListenProto::Tcp,
                bind_addr: IpAddr::V4(Ipv4Addr::from(row.dwLocalAddr.to_ne_bytes())),
                port: port_from_raw(row.dwLocalPort),
                pid: row.dwOwningPid,
            });
        }
    }
}

// ─── TCP IPv6 listeners ──────────────────────────────────────────────────────

fn enumerate_tcp6_listeners(result: &mut Vec<RawListener>) {
    unsafe {
        let mut size: u32 = 0;
        GetExtendedTcpTable(
            std::ptr::null_mut(),
            &mut size,
            0,
            AF_INET6,
            TCP_TABLE_OWNER_PID_LISTENER,
            0,
        );
        if size == 0 {
            return;
        }

        let mut buf = vec![0u8; size as usize];
        let ret = GetExtendedTcpTable(
            buf.as_mut_ptr(),
            &mut size,
            0,
            AF_INET6,
            TCP_TABLE_OWNER_PID_LISTENER,
            0,
        );
        if ret != NO_ERROR {
            return;
        }

        let table = &*(buf.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID);
        let num = table.dwNumEntries as usize;
        if num == 0 {
            return;
        }
        let rows = std::slice::from_raw_parts(table.table.as_ptr(), num);

        for row in rows {
            result.push(RawListener {
                proto: ListenProto::Tcp,
                bind_addr: IpAddr::V6(Ipv6Addr::from(row.ucLocalAddr)),
                port: port_from_raw(row.dwLocalPort),
                pid: row.dwOwningPid,
            });
        }
    }
}

// ─── UDP IPv4 listeners ──────────────────────────────────────────────────────

fn enumerate_udp4_listeners(result: &mut Vec<RawListener>) {
    unsafe {
        let mut size: u32 = 0;
        GetExtendedUdpTable(
            std::ptr::null_mut(),
            &mut size,
            0,
            AF_INET,
            UDP_TABLE_OWNER_PID,
            0,
        );
        if size == 0 {
            return;
        }

        let mut buf = vec![0u8; size as usize];
        let ret = GetExtendedUdpTable(
            buf.as_mut_ptr(),
            &mut size,
            0,
            AF_INET,
            UDP_TABLE_OWNER_PID,
            0,
        );
        if ret != NO_ERROR {
            return;
        }

        let table = &*(buf.as_ptr() as *const MIB_UDPTABLE_OWNER_PID);
        let num = table.dwNumEntries as usize;
        if num == 0 {
            return;
        }
        let rows = std::slice::from_raw_parts(table.table.as_ptr(), num);

        for row in rows {
            result.push(RawListener {
                proto: ListenProto::Udp,
                bind_addr: IpAddr::V4(Ipv4Addr::from(row.dwLocalAddr.to_ne_bytes())),
                port: port_from_raw(row.dwLocalPort),
                pid: row.dwOwningPid,
            });
        }
    }
}

// ─── UDP IPv6 listeners ──────────────────────────────────────────────────────

fn enumerate_udp6_listeners(result: &mut Vec<RawListener>) {
    unsafe {
        let mut size: u32 = 0;
        GetExtendedUdpTable(
            std::ptr::null_mut(),
            &mut size,
            0,
            AF_INET6,
            UDP_TABLE_OWNER_PID,
            0,
        );
        if size == 0 {
            return;
        }

        let mut buf = vec![0u8; size as usize];
        let ret = GetExtendedUdpTable(
            buf.as_mut_ptr(),
            &mut size,
            0,
            AF_INET6,
            UDP_TABLE_OWNER_PID,
            0,
        );
        if ret != NO_ERROR {
            return;
        }

        let table = &*(buf.as_ptr() as *const MIB_UDP6TABLE_OWNER_PID);
        let num = table.dwNumEntries as usize;
        if num == 0 {
            return;
        }
        let rows = std::slice::from_raw_parts(table.table.as_ptr(), num);

        for row in rows {
            result.push(RawListener {
                proto: ListenProto::Udp,
                bind_addr: IpAddr::V6(Ipv6Addr::from(row.ucLocalAddr)),
                port: port_from_raw(row.dwLocalPort),
                pid: row.dwOwningPid,
            });
        }
    }
}
