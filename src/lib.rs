use std::net::IpAddr;

#[cfg(test)]
mod test;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Interface {
    name: String,
    flags: u64,
    mac: [u8; 6],
    address: IpAddr,
    scope_id: Option<u32>,
    netmask: IpAddr,
}

impl Interface {
    /// Interface name, e.g., "lo".
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Interface flags. See libc::IFF_* flags.
    pub fn flags(&self) -> u64 {
        self.flags
    }

    /// MAC address, a.k.a., link-layer address, a.k.a., physical address.
    pub fn mac(&self) -> [u8; 6] {
        self.mac
    }

    /// Interface address.
    ///
    /// Note that [`ifa.address().is_loopback()`](std::net::IpAddr::is_loopback)
    /// returns false for link-local addresses such as fe80::1%lo0 although
    /// they are what would usually be thought of as "local" addresses.
    pub fn address(&self) -> &IpAddr {
        &self.address
    }

    /// IPv6 scope id or None.
    pub fn scope_id(&self) -> Option<u32> {
        self.scope_id
    }

    pub fn netmask(&self) -> &IpAddr {
        &self.netmask
    }

    /// Caveat emptor: follows the Node.js "192.168.0.42/24" convention
    /// instead of the arguably more common "192.168.0.0/24" notation.
    pub fn cidr(&self) -> (&IpAddr, u8) {
        let range = match self.netmask {
            IpAddr::V4(addr) => u32::from_be_bytes(addr.octets()).count_ones(),
            IpAddr::V6(addr) => u128::from_be_bytes(addr.octets()).count_ones(),
        };
        (&self.address, range as u8)
    }
}

#[cfg(target_os = "windows")]
pub use windows::*;

#[cfg(not(target_os = "windows"))]
pub use unix::*;

#[cfg(target_os = "windows")]
mod windows {
    use super::Interface;
    use std::io;
    use std::net;
    use std::net::IpAddr;
    use std::ptr::null_mut;
    use std::ptr::NonNull;
    use winapi::shared::ifdef::IfOperStatusUp;
    use winapi::shared::ws2def::SOCKADDR;
    use winapi::shared::ws2ipdef::SOCKADDR_IN6;
    use winapi::um::iphlpapi::GetAdaptersAddresses;
    use winapi::um::iptypes::GAA_FLAG_SKIP_ANYCAST;
    use winapi::um::iptypes::GAA_FLAG_SKIP_DNS_SERVER;
    use winapi::um::iptypes::GAA_FLAG_SKIP_MULTICAST;
    use winapi::um::iptypes::IP_ADAPTER_ADDRESSES;
    use winapi::um::iptypes::IP_ADAPTER_UNICAST_ADDRESS;
    use winapi::um::winsock2::PF_INET;
    use winapi::um::winsock2::PF_INET6;
    use winapi::um::winsock2::PF_UNSPEC;

    /// Returns an iterator that produces the list of interfaces that the
    /// operating system considers "up", that is, configured and active.
    pub fn up() -> io::Result<Up> {
        let mut len = 0;

        let flags = GAA_FLAG_SKIP_ANYCAST
            + GAA_FLAG_SKIP_DNS_SERVER
            + GAA_FLAG_SKIP_MULTICAST;

        // Fails with ERROR_BUFFER_OVERFLOW but updates |len| with actual size.
        unsafe {
            GetAdaptersAddresses(
                PF_UNSPEC as _,
                flags,
                null_mut(),
                null_mut(),
                &mut len,
            );
        }

        // Over-allocates 8x but easiest for proper alignment.
        let mut buf = vec![0usize; len as _];

        let result = unsafe {
            GetAdaptersAddresses(
                PF_UNSPEC as _,
                flags,
                null_mut(),
                buf.as_mut_ptr() as *mut _,
                &mut len,
            )
        };

        if result != 0 {
            return Err(io::Error::from_raw_os_error(result as _));
        }

        let adapter =
            NonNull::new(buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES);

        let address = adapter.and_then(|adapter| {
            let adapter = unsafe { adapter.as_ref() };
            NonNull::new(adapter.FirstUnicastAddress)
        });

        let iter = Iter { adapter, address };

        Ok(Up { _buf: buf, iter })
    }

    pub struct Up {
        _buf: Vec<usize>, // Over-allocates 8x but easiest for proper alignment.
        iter: Iter,
    }

    impl Iterator for Up {
        type Item = Interface;

        fn next(&mut self) -> Option<Self::Item> {
            self.iter.find_map(to_interface)
        }
    }

    impl Drop for Up {
        fn drop(&mut self) {}
    }

    struct Iter {
        adapter: Option<NonNull<IP_ADAPTER_ADDRESSES>>,
        address: Option<NonNull<IP_ADAPTER_UNICAST_ADDRESS>>,
    }

    impl Iterator for Iter {
        type Item = (
            NonNull<IP_ADAPTER_ADDRESSES>,
            NonNull<IP_ADAPTER_UNICAST_ADDRESS>,
        );

        fn next(&mut self) -> Option<Self::Item> {
            loop {
                let adapter = self.adapter?;

                if let Some(address) = self.address.take() {
                    self.address =
                        NonNull::new(unsafe { address.as_ref().Next });
                    return Some((adapter, address));
                }

                self.adapter = NonNull::new(unsafe { adapter.as_ref().Next });

                self.address = self.adapter.and_then(|adapter| {
                    let adapter = unsafe { adapter.as_ref() };
                    NonNull::new(adapter.FirstUnicastAddress)
                });
            }
        }
    }

    fn ip(addr: NonNull<SOCKADDR>) -> Option<IpAddr> {
        let family = unsafe { addr.as_ref().sa_family };

        // Leans on the fact that SocketAddrV4 and SocketAddrV6 are
        // transparent wrappers around SOCKADDR.
        match family as _ {
            PF_INET => {
                let addr = addr.as_ptr() as *const net::SocketAddrV4;
                Some(IpAddr::V4(*unsafe { *addr }.ip()))
            }
            PF_INET6 => {
                let addr = addr.as_ptr() as *const net::SocketAddrV6;
                Some(IpAddr::V6(*unsafe { *addr }.ip()))
            }
            _ => None,
        }
    }

    fn to_interface(
        (adapter, addr): (
            NonNull<IP_ADAPTER_ADDRESSES>,
            NonNull<IP_ADAPTER_UNICAST_ADDRESS>,
        ),
    ) -> Option<Interface> {
        let adapter = unsafe { adapter.as_ref() };

        if adapter.OperStatus != IfOperStatusUp {
            return None;
        }

        let addr = unsafe { addr.as_ref() };
        let sockaddr = NonNull::new(addr.Address.lpSockaddr)?;
        let prefixlen = addr.OnLinkPrefixLength as _;

        let address = ip(sockaddr)?;

        let netmask = match address {
            IpAddr::V4(_) => {
                let ones = !0u32;
                let mask = ones & !ones.checked_shr(prefixlen).unwrap_or(0);
                IpAddr::V4(net::Ipv4Addr::from(mask))
            }
            IpAddr::V6(_) => {
                let ones = !0u128;
                let mask = ones & !ones.checked_shr(prefixlen).unwrap_or(0);
                IpAddr::V6(net::Ipv6Addr::from(mask))
            }
        };

        let name =
            unsafe { std::slice::from_raw_parts(adapter.FriendlyName, 256) };
        let len = name.iter().position(|&b| b == 0).unwrap_or(name.len());
        let name = String::from_utf16_lossy(&name[..len]);

        let scope_id = address.is_ipv6().then(|| {
            let addr = addr.Address.lpSockaddr as *const SOCKADDR_IN6;
            unsafe { *(*addr).u.sin6_scope_id() }
        });

        let [b0, b1, b2, b3, b4, b5, _, _] = adapter.PhysicalAddress;
        let mac = [b0, b1, b2, b3, b4, b5];

        let flags = 0;

        Some(Interface {
            name,
            flags,
            mac,
            address,
            scope_id,
            netmask,
        })
    }
}

#[cfg(not(target_os = "windows"))]
mod unix {
    use super::Interface;
    use libc as c;
    use std::ffi::CStr;
    use std::io;
    use std::mem;
    use std::net;
    use std::net::IpAddr;
    use std::ptr;
    use std::ptr::NonNull;

    #[cfg(any(target_os = "android", target_os = "linux"))]
    use crate::linux::*;

    // Yes, wrong for Solaris's vile offspring. Don't complain, send patches.
    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    use crate::bsd::*;

    /// Returns an iterator that produces the list of interfaces that the
    /// operating system considers "up", that is, configured and active.
    pub fn up() -> io::Result<Up> {
        let mut base = ptr::null_mut();

        if 0 != unsafe { c::getifaddrs(&mut base) } {
            return Err(io::Error::last_os_error());
        }

        let base = NonNull::new(base);
        let iter = Iter(base);

        Ok(Up { base, iter })
    }

    pub struct Up {
        base: Option<NonNull<c::ifaddrs>>,
        iter: Iter,
    }

    impl Iterator for Up {
        type Item = Interface;

        fn next(&mut self) -> Option<Self::Item> {
            self.iter.find_map(|curr| to_interface(self.base, curr))
        }
    }

    impl Drop for Up {
        fn drop(&mut self) {
            if let Some(mut base) = self.base {
                unsafe { c::freeifaddrs(base.as_mut()) };
            }
        }
    }

    struct Iter(Option<NonNull<c::ifaddrs>>);

    impl Iterator for Iter {
        type Item = NonNull<c::ifaddrs>;

        fn next(&mut self) -> Option<Self::Item> {
            let curr = self.0?;
            let next = unsafe { curr.as_ref().ifa_next };
            mem::replace(&mut self.0, NonNull::new(next))
        }
    }

    fn ip(addr: NonNull<c::sockaddr>) -> Option<IpAddr> {
        let family = unsafe { addr.as_ref().sa_family };

        // Leans on the fact that SocketAddrV4 and SocketAddrV6 are
        // transparent wrappers around sockaddr_in and sockaddr_in6.
        match family as _ {
            c::AF_INET => {
                let addr = addr.as_ptr() as *const net::SocketAddrV4;
                Some(IpAddr::V4(*unsafe { *addr }.ip()))
            }
            c::AF_INET6 => {
                let addr = addr.as_ptr() as *const net::SocketAddrV6;
                Some(IpAddr::V6(*unsafe { *addr }.ip()))
            }
            _ => None,
        }
    }

    fn to_interface(
        base: Option<NonNull<c::ifaddrs>>,
        curr: NonNull<c::ifaddrs>,
    ) -> Option<Interface> {
        let curr = unsafe { curr.as_ref() };
        let addr = NonNull::new(curr.ifa_addr)?;

        if is_link(addr) {
            return None;
        }

        let address = ip(addr)?;
        let netmask = NonNull::new(curr.ifa_netmask).and_then(ip)?;

        let name = unsafe { CStr::from_ptr(curr.ifa_name) };
        let mac = Iter(base)
            .find_map(|link| mac_of(name, link))
            .unwrap_or_default();
        let name = name.to_string_lossy().into_owned();

        let flags = From::from(curr.ifa_flags);

        let scope_id = address.is_ipv6().then(|| {
            let addr = addr.as_ptr() as *const c::sockaddr_in6;
            unsafe { (*addr).sin6_scope_id }
        });

        Some(Interface {
            name,
            flags,
            mac,
            address,
            scope_id,
            netmask,
        })
    }
}

#[cfg(any(target_os = "android", target_os = "linux"))]
mod linux {
    use libc as c;
    use std::ffi::CStr;
    use std::ptr::NonNull;

    pub(crate) fn is_link(addr: NonNull<c::sockaddr>) -> bool {
        c::AF_PACKET == unsafe { addr.as_ref().sa_family } as _
    }

    pub(crate) fn mac_of(
        name: &CStr,
        link: NonNull<c::ifaddrs>,
    ) -> Option<[u8; 6]> {
        let link = unsafe { link.as_ref() };
        let addr = NonNull::new(link.ifa_addr)?;

        if !is_link(addr) {
            return None;
        }

        let ok = unsafe { CStr::from_ptr(link.ifa_name) }
            .to_bytes()
            .strip_prefix(name.to_bytes())
            .filter(|suffix| suffix.is_empty() || suffix.starts_with(b":"))
            .is_some();

        if !ok {
            return None;
        }

        let addr = link.ifa_addr as *const _ as *const c::sockaddr_ll;
        let addr = unsafe { &*addr };

        if addr.sll_halen != 6 {
            return None;
        }

        let [b0, b1, b2, b3, b4, b5, _, _] = addr.sll_addr;

        Some([b0, b1, b2, b3, b4, b5])
    }
}

#[cfg(all(unix, not(any(target_os = "android", target_os = "linux"))))]
mod bsd {
    use libc as c;
    use std::ffi::CStr;
    use std::ptr::NonNull;

    pub(crate) fn is_link(addr: NonNull<c::sockaddr>) -> bool {
        c::AF_LINK == unsafe { addr.as_ref().sa_family } as _
    }

    pub(crate) fn mac_of(
        name: &CStr,
        link: NonNull<c::ifaddrs>,
    ) -> Option<[u8; 6]> {
        let link = unsafe { link.as_ref() };
        let addr = NonNull::new(link.ifa_addr)?;

        if !is_link(addr) {
            return None;
        }

        let ok = unsafe { CStr::from_ptr(link.ifa_name) }
            .to_bytes()
            .strip_prefix(name.to_bytes())
            .filter(|suffix| suffix.is_empty() || suffix.starts_with(b":"))
            .is_some();

        if !ok {
            return None;
        }

        let addr = link.ifa_addr as *const _ as *const c::sockaddr_dl;
        let addr = unsafe { &*addr };

        if addr.sdl_alen != 6 {
            return None;
        }

        // sdl data contains both the if name and link-level address.
        // See: https://illumos.org/man/3socket/sockaddr_dl
        let start = addr.sdl_nlen as usize; // length of the if name.
        let end = start + addr.sdl_alen as usize;
        let data = unsafe {
            std::slice::from_raw_parts(&addr.sdl_data as *const _ as *const u8, end)
        };

        if let [b0, b1, b2, b3, b4, b5] = data[start..end] {
            Some([b0, b1, b2, b3, b4, b5])
        } else {
            None
        }
    }
}

#[test]
fn basic() {
    for ifa in up().unwrap() {
        println!("{:?} {:?}", ifa, ifa.cidr());

        assert!(!ifa.name().is_empty());
        assert!(ifa.address().is_ipv4() ^ ifa.scope_id().is_some());
        assert_eq!(ifa.address().is_ipv4(), ifa.netmask().is_ipv4());

        let link_local = "fe80::1" == &format!("{:?}", ifa.address());

        if link_local || ifa.address().is_loopback() {
            let (address, range) = ifa.cidr();
            assert_eq!(address, ifa.address());
            match address {
                IpAddr::V6(_) if link_local => assert_eq!(range, 64),
                IpAddr::V6(_) => assert_eq!(range, 128),
                IpAddr::V4(_) => assert_eq!(range, 8),
            }
        }
    }
}
