use crate::up;
use std::process::Command;

/// Make sure the mac addresses returned by netif match those returned by ifconfig.
#[test]
fn test_mac_addresses() {
    for interface in up().unwrap() {
        if interface.mac() == ZERO_MAC {
            // lo0 and others don't have mac addresses:
            println!("Skipping {} {}", interface.name(), interface.address);
            continue;
        }

        let mac = mac_hex(interface.mac());
        let macos_mac = ifconfig_mac(interface.name()).expect("mac");
        assert_eq!(mac, macos_mac, "interface: {:#?}", interface);
    }
}

const ZERO_MAC: [u8; 6] = [0; 6];

fn ifconfig_mac(if_name: &str) -> Option<String> {
    let output = Command::new("/sbin/ifconfig")
        .arg(if_name)
        .output()
        .expect("Error running ifconfig");

    let stdout = String::from_utf8(output.stdout).expect("Parsing stdout");
    return stdout
        .lines()
        .map(str::trim)
        .flat_map(|x| x.strip_prefix("ether "))
        .map(|x| x.to_string())
        .next();
}

fn mac_hex(mac: [u8; 6]) -> String {
    use std::fmt::Write;

    let mut s = String::new();
    write!(s, "{:02x}", mac[0]).unwrap();
    for byte in &mac[1..] {
        write!(s, ":{byte:02x}").unwrap();
    }
    s
}
