//! Enumerates all listening TCP and UDP ports on the local machine using
//! Windows `GetExtendedTcpTable` / `GetExtendedUdpTable` APIs.
//!
//! Performance: uses `TCP_TABLE_OWNER_PID_LISTENER` class (value 3) which
//! returns ONLY listening sockets — much faster than `TCP_TABLE_OWNER_PID_ALL`.
//! Typical call completes in 1-5 ms.

use std::collections::{HashMap, HashSet};
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

// ─── Windows SCM FFI (advapi32) for svchost service resolution ──────────────

#[link(name = "advapi32")]
extern "system" {
    fn OpenSCManagerW(
        lpMachineName: *const u16,
        lpDatabaseName: *const u16,
        dwDesiredAccess: u32,
    ) -> *mut std::ffi::c_void;

    fn EnumServicesStatusExW(
        hSCManager: *mut std::ffi::c_void,
        InfoLevel: u32,
        dwServiceType: u32,
        dwServiceState: u32,
        lpServices: *mut u8,
        cbBufSize: u32,
        pcbBytesNeeded: *mut u32,
        lpServicesReturned: *mut u32,
        lpResumeHandle: *mut u32,
        pszGroupName: *const u16,
    ) -> i32;

    fn CloseServiceHandle(hSCObject: *mut std::ffi::c_void) -> i32;
}

const SC_MANAGER_ENUMERATE_SERVICE: u32 = 0x0004;
const SC_ENUM_PROCESS_INFO: u32 = 0;
const SERVICE_WIN32: u32 = 0x30;
const SERVICE_ACTIVE: u32 = 0x01;

#[repr(C)]
#[allow(non_snake_case, non_camel_case_types)]
struct ENUM_SERVICE_STATUS_PROCESSW {
    lpServiceName: *const u16,
    lpDisplayName: *const u16,
    ServiceStatusProcess: SERVICE_STATUS_PROCESS,
}

#[repr(C)]
#[allow(non_snake_case, non_camel_case_types)]
struct SERVICE_STATUS_PROCESS {
    dwServiceType: u32,
    dwCurrentState: u32,
    dwControlsAccepted: u32,
    dwWin32ExitCode: u32,
    dwServiceSpecificExitCode: u32,
    dwCheckPoint: u32,
    dwWaitHint: u32,
    dwProcessId: u32,
    dwServiceFlags: u32,
}

/// Read a null-terminated UTF-16 string from a raw pointer.
unsafe fn wstr_to_string(ptr: *const u16) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let mut len = 0;
    while *ptr.add(len) != 0 {
        len += 1;
    }
    String::from_utf16_lossy(std::slice::from_raw_parts(ptr, len))
}

/// Resolve Windows service names for a set of PIDs using the SCM API.
/// Returns a map of PID -> Vec<service_name> (lowercase).
/// Equivalent to `tasklist /svc` for the given PIDs.
pub fn resolve_service_names(pids: &[u32]) -> HashMap<u32, Vec<String>> {
    let mut result: HashMap<u32, Vec<String>> = HashMap::new();
    if pids.is_empty() {
        return result;
    }

    let pid_set: HashSet<u32> = pids.iter().copied().collect();

    unsafe {
        let scm = OpenSCManagerW(
            std::ptr::null(),
            std::ptr::null(),
            SC_MANAGER_ENUMERATE_SERVICE,
        );
        if scm.is_null() {
            return result;
        }

        // First call to get required buffer size
        let mut bytes_needed: u32 = 0;
        let mut services_returned: u32 = 0;
        let mut resume_handle: u32 = 0;

        EnumServicesStatusExW(
            scm,
            SC_ENUM_PROCESS_INFO,
            SERVICE_WIN32,
            SERVICE_ACTIVE,
            std::ptr::null_mut(),
            0,
            &mut bytes_needed,
            &mut services_returned,
            &mut resume_handle,
            std::ptr::null(),
        );

        if bytes_needed == 0 {
            CloseServiceHandle(scm);
            return result;
        }

        // Allocate buffer and enumerate
        let buf_size = bytes_needed;
        let mut buf = vec![0u8; buf_size as usize];
        resume_handle = 0;
        services_returned = 0;

        let ret = EnumServicesStatusExW(
            scm,
            SC_ENUM_PROCESS_INFO,
            SERVICE_WIN32,
            SERVICE_ACTIVE,
            buf.as_mut_ptr(),
            buf_size,
            &mut bytes_needed,
            &mut services_returned,
            &mut resume_handle,
            std::ptr::null(),
        );

        if ret == 0 && services_returned == 0 {
            CloseServiceHandle(scm);
            return result;
        }

        let entries = std::slice::from_raw_parts(
            buf.as_ptr() as *const ENUM_SERVICE_STATUS_PROCESSW,
            services_returned as usize,
        );

        for entry in entries {
            let pid = entry.ServiceStatusProcess.dwProcessId;
            if pid == 0 || !pid_set.contains(&pid) {
                continue;
            }
            let name = wstr_to_string(entry.lpServiceName).to_lowercase();
            result.entry(pid).or_default().push(name);
        }

        CloseServiceHandle(scm);
    }

    result
}

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
///
/// For svchost.exe processes where the command line is empty (common when running
/// without elevated privileges), queries the Windows Service Control Manager to
/// resolve the hosted service name(s) and populates the cmdline field.
pub fn resolve_process_info(pids: &[u32]) -> HashMap<u32, ProcessInfo> {
    let mut map = HashMap::new();
    if pids.is_empty() {
        return map;
    }

    let mut sys = System::new();
    let sysinfo_pids: Vec<Pid> = pids.iter().map(|&p| Pid::from_u32(p)).collect();
    sys.refresh_processes(ProcessesToUpdate::Some(&sysinfo_pids), true);

    // Collect svchost PIDs that need service name resolution
    let mut svchost_pids: Vec<u32> = Vec::new();

    for &pid in pids {
        if let Some(proc) = sys.process(Pid::from_u32(pid)) {
            let name = proc.name().to_string_lossy().to_string();
            let exe_path = proc
                .exe()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default();
            let cmdline = proc.cmd().iter().map(|s| s.to_string_lossy()).collect::<Vec<_>>().join(" ");

            if name.eq_ignore_ascii_case("svchost.exe") && cmdline.is_empty() {
                svchost_pids.push(pid);
            }

            map.insert(pid, ProcessInfo {
                name,
                exe_path,
                cmdline,
            });
        }
    }

    // Resolve service names for svchost.exe processes with empty cmdlines
    if !svchost_pids.is_empty() {
        let svc_map = resolve_service_names(&svchost_pids);
        for (pid, services) in svc_map {
            if let Some(info) = map.get_mut(&pid) {
                if info.cmdline.is_empty() {
                    info.cmdline = format!("svchost.exe -k {}", services.join(","));
                }
            }
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
