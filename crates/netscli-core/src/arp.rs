mod platform;
mod types;

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use ipnet::IpNet;
use mac_address::MacAddress;

use crate::error::Result;
use crate::oui::lookup_vendor;

pub use types::{ArpEntry, InterfaceInfo};

pub struct NetworkManager;

impl NetworkManager {
    /// The MAC for `ip`: from the neighbour table, from this machine's own
    /// interfaces when `ip` is one of its addresses, or, on Windows, by
    /// asking `ip` over ARP from the interface whose subnet holds it.
    ///
    /// Blocking. The ARP request can take about 4 s when nothing answers, so
    /// callers with a deadline should bound it.
    pub fn find_mac(ip: &IpAddr) -> Option<ArpEntry> {
        if let Some(entry) = Self::get_arp_table()
            .ok()
            .and_then(|table| table.into_iter().find(|e| &e.ip == ip))
        {
            return Some(entry);
        }
        let interfaces = Self::get_interfaces();
        if let Some(entry) = own_entry(*ip, &interfaces) {
            return Some(entry);
        }
        #[cfg(target_os = "windows")]
        if let IpAddr::V4(v4) = ip {
            let src = on_link_source(*v4, &interfaces)?;
            let mac = platform::resolve(*v4, Some(src))?;
            return Some(entry(*ip, mac, src.to_string()));
        }
        None
    }

    pub fn get_interfaces() -> Vec<InterfaceInfo> {
        platform::get_interfaces()
    }

    pub fn get_arp_table() -> Result<Vec<ArpEntry>> {
        platform::get_arp_table()
    }

    pub fn add_entry(ip: IpAddr, mac: MacAddress) -> Result<()> {
        platform::add_entry(ip, mac)
    }

    pub fn delete_entry(ip: IpAddr) -> Result<()> {
        platform::delete_entry(ip)
    }

    pub fn clear_table() -> Result<()> {
        platform::clear_table()
    }
}

/// Which of `candidates` answer ARP within `wait`, for discovery's
/// table-only neighbours. On Windows the neighbour table keeps devices that
/// have gone (see platform/windows_resolve.rs), so each is asked again. On
/// Linux and macOS this is not measured yet and every candidate is kept, as
/// before.
pub(crate) async fn still_present(candidates: &[Ipv4Addr], wait: Duration) -> HashSet<Ipv4Addr> {
    #[cfg(target_os = "windows")]
    {
        resolve_macs(candidates, wait).await.into_keys().collect()
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = wait;
        candidates.iter().copied().collect()
    }
}

/// The MAC each of `candidates` answers ARP with, for the ones that answer
/// within `wait`. Each request leaves from the local interface whose subnet
/// holds the candidate; a candidate on no attached subnet is not asked,
/// since ARP cannot reach it.
///
/// Windows only. Elsewhere this returns nothing and callers keep what the
/// neighbour table had.
pub(crate) async fn resolve_macs(
    candidates: &[Ipv4Addr],
    wait: Duration,
) -> HashMap<Ipv4Addr, ArpEntry> {
    #[cfg(target_os = "windows")]
    {
        use futures::stream::StreamExt;

        // Lookups in flight at once. All of them used to start together, and
        // each `wait` was counted from then, so with more candidates than
        // tokio's blocking pool has threads, lookups spent their time queued
        // and real neighbours were dropped. Now `wait` starts when a lookup
        // does.
        const AT_ONCE: usize = 64;

        let interfaces = tokio::task::spawn_blocking(platform::get_interfaces)
            .await
            .unwrap_or_default();
        // By value: a closure over `&Ipv4Addr` makes the stream's future not
        // `Send` for every lifetime, which `tokio::spawn` in discovery needs.
        let checks = candidates
            .iter()
            .filter_map(|ip| Some((*ip, on_link_source(*ip, &interfaces)?)))
            .collect::<Vec<_>>()
            .into_iter()
            .map(|(ip, src)| async move {
                // A lookup that outlives `wait` keeps its blocking thread
                // until Windows gives up on it, about 4 s; its answer is just
                // ignored.
                let asked = tokio::task::spawn_blocking(move || platform::resolve(ip, Some(src)));
                match tokio::time::timeout(wait, asked).await {
                    Ok(Ok(Some(mac))) => Some((ip, entry(IpAddr::V4(ip), mac, src.to_string()))),
                    _ => None,
                }
            });
        futures::stream::iter(checks)
            .buffer_unordered(AT_ONCE)
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .flatten()
            .collect()
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (candidates, wait);
        HashMap::new()
    }
}

/// An entry for `ip` when it is one of this machine's own addresses. The
/// neighbour table never lists those, so discovery reported the scanning
/// machine without a MAC on every subnet it scanned.
pub(crate) fn own_entry(ip: IpAddr, interfaces: &[InterfaceInfo]) -> Option<ArpEntry> {
    interfaces
        .iter()
        .filter(|iface| !iface.is_loopback)
        .find_map(|iface| {
            let mac = iface.mac.filter(|m| m.bytes() != [0; 6])?;
            iface
                .ips
                .iter()
                .any(|net| net.addr() == ip)
                .then(|| entry(ip, mac, iface.name.clone()))
        })
}

/// The local IPv4 address to send an ARP request for `target` from: an
/// address on an up, non-loopback interface with a hardware address, whose
/// subnet holds `target`. The most specific subnet wins. `None` when
/// `target` is on no attached subnet, where ARP cannot reach it.
///
/// The hardware-address check leaves out tunnels such as WireGuard, which
/// have no link layer to ARP on even when they route the same range.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub(crate) fn on_link_source(target: Ipv4Addr, interfaces: &[InterfaceInfo]) -> Option<Ipv4Addr> {
    interfaces
        .iter()
        .filter(|iface| iface.is_up && !iface.is_loopback)
        .filter(|iface| iface.mac.is_some_and(|m| m.bytes() != [0; 6]))
        .flat_map(|iface| iface.ips.iter())
        .filter_map(|net| match net {
            IpNet::V4(net) if net.prefix_len() < 32 && net.addr() != target => Some(*net),
            _ => None,
        })
        .filter(|net| net.contains(&target))
        .max_by_key(|net| net.prefix_len())
        .map(|net| net.addr())
}

fn entry(ip: IpAddr, mac: MacAddress, interface: String) -> ArpEntry {
    ArpEntry {
        ip,
        mac,
        interface,
        vendor: lookup_vendor(&mac.to_string()),
    }
}

#[cfg(test)]
mod source_tests {
    use super::*;

    fn iface(name: &str, mac: Option<[u8; 6]>, ips: &[&str], is_up: bool) -> InterfaceInfo {
        InterfaceInfo {
            name: name.to_string(),
            mac: mac.map(MacAddress::new),
            ips: ips.iter().map(|s| s.parse().unwrap()).collect(),
            is_up,
            is_loopback: false,
        }
    }

    const NIC: [u8; 6] = [0x6c, 0x3c, 0x8c, 0x01, 0x02, 0x03];

    // The case that hid 312 of 343 MACs: a WireGuard tunnel routes the LAN,
    // and the Ethernet adapter that is actually on it has to be chosen.
    #[test]
    fn the_ethernet_address_is_chosen_over_a_tunnel_routing_the_same_range() {
        let interfaces = vec![
            iface("wt0", None, &["100.76.7.136/16"], true),
            iface(
                "Ethernet 4",
                Some(NIC),
                &["192.168.100.250/24", "192.1.3.50/22"],
                true,
            ),
        ];
        let target = "192.1.0.11".parse().unwrap();
        assert_eq!(
            on_link_source(target, &interfaces),
            Some("192.1.3.50".parse().unwrap())
        );
    }

    #[test]
    fn an_address_on_no_attached_subnet_has_no_source() {
        let interfaces = vec![iface("Ethernet", Some(NIC), &["192.168.1.5/24"], true)];
        assert_eq!(
            on_link_source("10.0.0.1".parse().unwrap(), &interfaces),
            None
        );
    }

    #[test]
    fn a_down_interface_or_a_host_route_is_not_a_source() {
        let interfaces = vec![
            iface("Down", Some(NIC), &["192.168.1.5/24"], false),
            iface("Up", Some(NIC), &["192.168.1.6/32"], true),
        ];
        assert_eq!(
            on_link_source("192.168.1.9".parse().unwrap(), &interfaces),
            None
        );
    }

    #[test]
    fn the_most_specific_subnet_wins() {
        let interfaces = vec![
            iface("Wide", Some(NIC), &["10.0.0.5/8"], true),
            iface("Narrow", Some(NIC), &["10.1.2.5/24"], true),
        ];
        assert_eq!(
            on_link_source("10.1.2.9".parse().unwrap(), &interfaces),
            Some("10.1.2.5".parse().unwrap())
        );
    }

    #[test]
    fn the_machines_own_address_gets_its_interface_mac() {
        let interfaces = vec![iface("Ethernet 4", Some(NIC), &["192.1.3.50/22"], true)];
        let own = own_entry("192.1.3.50".parse().unwrap(), &interfaces).expect("own entry");
        assert_eq!(own.mac.bytes(), NIC);
        assert_eq!(own.interface, "Ethernet 4");
        assert!(own_entry("192.1.3.51".parse().unwrap(), &interfaces).is_none());
    }
}

#[cfg(all(test, target_os = "windows"))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_neighbour_that_does_not_answer_arp_is_dropped() {
        // TEST-NET-1 (RFC 5737): never assigned, so nothing can answer.
        let gone = Ipv4Addr::new(192, 0, 2, 77);
        let present = still_present(&[gone], Duration::from_millis(300)).await;
        assert!(present.is_empty(), "kept {present:?}");
    }
}
