use std::net::IpAddr;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Interface {
    name: String,
    flags: u32,
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
    pub fn flags(&self) -> u32 {
        self.flags
    }

    /// MAC address, a.k.a., link-layer address, a.k.a., physical address.
    pub fn mac(&self) -> [u8; 6] {
        self.mac
    }

    /// Interface address. Reader beware: `ifa.address().is_loopback()`
    /// returns false for fe80::1%lo0 even though that is a local address;
    /// it's a link-local address attached to the loopback interface.
    /// See https://github.com/rust-lang/rust/issues/91448
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

    pub fn all() -> io::Result<All> {
        Ok(All)
    }

    pub struct All;

    impl Iterator for All {
        type Item = Interface;

        fn next(&mut self) -> Option<Self::Item> {
            None
        }
    }

    impl Drop for All {
        fn drop(&mut self) {}
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

    #[cfg(target_os = "linux")]
    use crate::linux::*;

    #[cfg(target_os = "macos")]
    use crate::macos::*;

    pub fn all() -> io::Result<All> {
        let mut base = ptr::null_mut();

        if 0 != unsafe { c::getifaddrs(&mut base) } {
            return Err(io::Error::last_os_error());
        }

        let base = NonNull::new(base);
        let iter = Iter(base);

        Ok(All { base, iter })
    }

    pub struct All {
        base: Option<NonNull<c::ifaddrs>>,
        iter: Iter,
    }

    impl Iterator for All {
        type Item = Interface;

        fn next(&mut self) -> Option<Self::Item> {
            self.iter.find_map(|curr| to_interface(self.base, curr))
        }
    }

    impl Drop for All {
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
        // Leans on the fact that SocketAddrV4 and SocketAddrV6 are
        // transparent wrappers around sockaddr_in and sockaddr_in6.
        match unsafe { addr.as_ref().sa_family } as _ {
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

        let flags = curr.ifa_flags;

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

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "macos")]
mod macos {
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

        let [b0, b1, b2, b3, b4, b5, _, _, _, _, _, _] = addr.sdl_data;

        Some([b0 as u8, b1 as u8, b2 as u8, b3 as u8, b4 as u8, b5 as u8])
    }
}

#[test]
fn basic() {
    for ifa in all().unwrap() {
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
