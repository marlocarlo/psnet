use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::types::{ConnProto, Connection, PidCache, TcpState};
use crate::utils::ntohs;

use sysinfo::{Pid, ProcessesToUpdate, System};

// ─── Win32 API structs ───────────────────────────────────────────────────────

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

const AF_INET: u32 = 2;
const AF_INET6: u32 = 23;
const TCP_TABLE_OWNER_PID_ALL: u32 = 5;
const UDP_TABLE_OWNER_PID: u32 = 1;

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

#[link(name = "kernel32")]
extern "system" {
    fn OpenProcess(
        dwDesiredAccess: u32,
        bInheritHandle: i32,
        dwProcessId: u32,
    ) -> *mut std::ffi::c_void;
    fn CloseHandle(hObject: *mut std::ffi::c_void) -> i32;
    fn QueryFullProcessImageNameW(
        hProcess: *mut std::ffi::c_void,
        dwFlags: u32,
        lpExeName: *mut u16,
        lpdwSize: *mut u32,
    ) -> i32;
}

const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;

// ─── Process name resolution ─────────────────────────────────────────────────

pub fn get_process_name(pid: u32) -> String {
    if pid == 0 {
        return "[Kernel]".to_string();
    }
    if pid == 4 {
        return "System".to_string();
    }

    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if handle.is_null() {
            return format!("PID:{}", pid);
        }
        let mut buf = [0u16; 1024];
        let mut size: u32 = 1024;
        let ok = QueryFullProcessImageNameW(handle, 0, buf.as_mut_ptr(), &mut size);
        CloseHandle(handle);
        if ok == 0 || size == 0 {
            return format!("PID:{}", pid);
        }
        let path = String::from_utf16_lossy(&buf[..size as usize]);
        path.rsplit('\\')
            .next()
            .unwrap_or(&path)
            .to_string()
    }
}

// ─── Fetch all connections ───────────────────────────────────────────────────

pub fn fetch_connections(pid_cache: &mut PidCache) -> Vec<Connection> {
    let mut conns = Vec::with_capacity(512);

    fetch_tcp4(&mut conns);
    fetch_tcp6(&mut conns);
    fetch_udp4(&mut conns);
    fetch_udp6(&mut conns);

    // Collect PIDs that need resolution
    let unresolved: Vec<u32> = conns.iter()
        .map(|c| c.pid)
        .filter(|pid| !pid_cache.contains_key(pid))
        .collect();

    if !unresolved.is_empty() {
        // Try Win32 API first, then fall back to sysinfo for failures
        let mut needs_sysinfo = Vec::new();
        for &pid in &unresolved {
            let name = get_process_name(pid);
            if name.starts_with("PID:") {
                needs_sysinfo.push(pid);
            } else {
                pid_cache.insert(pid, name);
            }
        }

        // Sysinfo fallback for unresolved PIDs
        if !needs_sysinfo.is_empty() {
            let mut sys = System::new();
            let pids: Vec<Pid> = needs_sysinfo.iter().map(|&p| Pid::from_u32(p)).collect();
            sys.refresh_processes(ProcessesToUpdate::Some(&pids), true);
            for &pid in &needs_sysinfo {
                if let Some(proc) = sys.process(Pid::from_u32(pid)) {
                    pid_cache.insert(pid, proc.name().to_string_lossy().to_string());
                }
                // Don't cache failures — retry next tick
            }
        }
    }

    for conn in &mut conns {
        if let Some(name) = pid_cache.get(&conn.pid) {
            conn.process_name = name.clone();
        } else if conn.pid != 0 {
            conn.process_name = format!("PID:{}", conn.pid);
        }
    }

    conns
}

fn fetch_tcp4(conns: &mut Vec<Connection>) {
    unsafe {
        let mut size: u32 = 0;
        GetExtendedTcpTable(
            std::ptr::null_mut(), &mut size, 0, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0,
        );
        if size == 0 { return; }
        let mut buf = vec![0u8; size as usize];
        let ret = GetExtendedTcpTable(
            buf.as_mut_ptr(), &mut size, 0, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0,
        );
        if ret != 0 { return; }
        let table = &*(buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
        let rows = std::slice::from_raw_parts(
            table.table.as_ptr(), table.dwNumEntries as usize,
        );
        for row in rows {
            conns.push(Connection {
                proto: ConnProto::Tcp,
                local_addr: IpAddr::V4(Ipv4Addr::from(row.dwLocalAddr.to_ne_bytes())),
                local_port: ntohs(row.dwLocalPort),
                remote_addr: Some(IpAddr::V4(Ipv4Addr::from(row.dwRemoteAddr.to_ne_bytes()))),
                remote_port: Some(ntohs(row.dwRemotePort)),
                state: Some(TcpState::from_raw(row.dwState)),
                pid: row.dwOwningPid,
                process_name: String::new(),
                dns_hostname: None,
            });
        }
    }
}

fn fetch_tcp6(conns: &mut Vec<Connection>) {
    unsafe {
        let mut size: u32 = 0;
        GetExtendedTcpTable(
            std::ptr::null_mut(), &mut size, 0, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0,
        );
        if size == 0 { return; }
        let mut buf = vec![0u8; size as usize];
        let ret = GetExtendedTcpTable(
            buf.as_mut_ptr(), &mut size, 0, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0,
        );
        if ret != 0 { return; }
        let table = &*(buf.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID);
        let rows = std::slice::from_raw_parts(
            table.table.as_ptr(), table.dwNumEntries as usize,
        );
        for row in rows {
            conns.push(Connection {
                proto: ConnProto::Tcp,
                local_addr: IpAddr::V6(Ipv6Addr::from(row.ucLocalAddr)),
                local_port: ntohs(row.dwLocalPort),
                remote_addr: Some(IpAddr::V6(Ipv6Addr::from(row.ucRemoteAddr))),
                remote_port: Some(ntohs(row.dwRemotePort)),
                state: Some(TcpState::from_raw(row.dwState)),
                pid: row.dwOwningPid,
                process_name: String::new(),
                dns_hostname: None,
            });
        }
    }
}

fn fetch_udp4(conns: &mut Vec<Connection>) {
    unsafe {
        let mut size: u32 = 0;
        GetExtendedUdpTable(
            std::ptr::null_mut(), &mut size, 0, AF_INET, UDP_TABLE_OWNER_PID, 0,
        );
        if size == 0 { return; }
        let mut buf = vec![0u8; size as usize];
        let ret = GetExtendedUdpTable(
            buf.as_mut_ptr(), &mut size, 0, AF_INET, UDP_TABLE_OWNER_PID, 0,
        );
        if ret != 0 { return; }
        let table = &*(buf.as_ptr() as *const MIB_UDPTABLE_OWNER_PID);
        let rows = std::slice::from_raw_parts(
            table.table.as_ptr(), table.dwNumEntries as usize,
        );
        for row in rows {
            conns.push(Connection {
                proto: ConnProto::Udp,
                local_addr: IpAddr::V4(Ipv4Addr::from(row.dwLocalAddr.to_ne_bytes())),
                local_port: ntohs(row.dwLocalPort),
                remote_addr: None,
                remote_port: None,
                state: None,
                pid: row.dwOwningPid,
                process_name: String::new(),
                dns_hostname: None,
            });
        }
    }
}

fn fetch_udp6(conns: &mut Vec<Connection>) {
    unsafe {
        let mut size: u32 = 0;
        GetExtendedUdpTable(
            std::ptr::null_mut(), &mut size, 0, AF_INET6, UDP_TABLE_OWNER_PID, 0,
        );
        if size == 0 { return; }
        let mut buf = vec![0u8; size as usize];
        let ret = GetExtendedUdpTable(
            buf.as_mut_ptr(), &mut size, 0, AF_INET6, UDP_TABLE_OWNER_PID, 0,
        );
        if ret != 0 { return; }
        let table = &*(buf.as_ptr() as *const MIB_UDP6TABLE_OWNER_PID);
        let rows = std::slice::from_raw_parts(
            table.table.as_ptr(), table.dwNumEntries as usize,
        );
        for row in rows {
            conns.push(Connection {
                proto: ConnProto::Udp,
                local_addr: IpAddr::V6(Ipv6Addr::from(row.ucLocalAddr)),
                local_port: ntohs(row.dwLocalPort),
                remote_addr: None,
                remote_port: None,
                state: None,
                pid: row.dwOwningPid,
                process_name: String::new(),
                dns_hostname: None,
            });
        }
    }
}
