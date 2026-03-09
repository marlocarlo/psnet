use std::collections::HashMap;
use std::sync::OnceLock;

static OUI_DB: OnceLock<HashMap<[u8; 3], &'static str>> = OnceLock::new();

fn parse_hex_byte(s: &str) -> Option<u8> {
    u8::from_str_radix(s, 16).ok()
}

fn get_db() -> &'static HashMap<[u8; 3], &'static str> {
    OUI_DB.get_or_init(|| {
        let raw = include_str!("../../data/oui.txt");
        let mut map = HashMap::with_capacity(32000);
        for line in raw.lines() {
            if let Some((hex, name)) = line.split_once('\t') {
                let hex = hex.trim();
                if hex.len() == 6 {
                    if let (Some(a), Some(b), Some(c)) = (
                        parse_hex_byte(&hex[0..2]),
                        parse_hex_byte(&hex[2..4]),
                        parse_hex_byte(&hex[4..6]),
                    ) {
                        map.insert([a, b, c], name.trim());
                    }
                }
            }
        }
        map
    })
}

/// Look up the manufacturer for a MAC address like "AA:BB:CC:DD:EE:FF".
pub fn lookup(mac: &str) -> Option<&'static str> {
    let clean: String = mac.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if clean.len() < 6 {
        return None;
    }
    let prefix = [
        parse_hex_byte(&clean[0..2])?,
        parse_hex_byte(&clean[2..4])?,
        parse_hex_byte(&clean[4..6])?,
    ];
    get_db().get(&prefix).copied()
}
