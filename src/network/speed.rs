use sysinfo::Networks;

/// Aggregate received/sent bytes across all network interfaces.
/// Returns (total_recv, total_sent, most_active_interface_name).
pub fn get_network_bytes(networks: &Networks) -> (u64, u64, String) {
    let mut total_recv: u64 = 0;
    let mut total_sent: u64 = 0;
    let mut iface_name = String::from("No Interface");
    let mut best_traffic: u64 = 0;

    for (name, data) in networks.iter() {
        let r = data.total_received();
        let s = data.total_transmitted();
        total_recv += r;
        total_sent += s;
        if r + s > best_traffic {
            best_traffic = r + s;
            iface_name = name.to_string();
        }
    }
    (total_recv, total_sent, iface_name)
}
