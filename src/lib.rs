use libc as c;
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
    pub fn is_broadcast(&self) -> bool {
        0 != self.flags & c::IFF_BROADCAST as u32
    }

    pub fn is_loopback(&self) -> bool {
        0 != self.flags & c::IFF_LOOPBACK as u32
    }

    pub fn is_multicast(&self) -> bool {
        0 != self.flags & c::IFF_MULTICAST as u32
    }

    pub fn is_noarp(&self) -> bool {
        0 != self.flags & c::IFF_NOARP as u32
    }

    pub fn is_point_to_point(&self) -> bool {
        0 != self.flags & c::IFF_POINTOPOINT as u32
    }

    pub fn is_promiscuous(&self) -> bool {
        0 != self.flags & c::IFF_PROMISC as u32
    }

    pub fn is_running(&self) -> bool {
        0 != self.flags & c::IFF_RUNNING as u32
    }

    pub fn is_up(&self) -> bool {
        0 != self.flags & c::IFF_UP as u32
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn flags(&self) -> u32 {
        self.flags
    }

    pub fn mac(&self) -> [u8; 6] {
        self.mac
    }

    pub fn address(&self) -> &IpAddr {
        &self.address
    }

    pub fn scope_id(&self) -> Option<u32> {
        self.scope_id
    }

    pub fn netmask(&self) -> &IpAddr {
        &self.netmask
    }
}

#[cfg(not(target_os = "windows"))]
pub use unix::*;

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

    fn family(addr: *const c::sockaddr) -> Option<i32> {
        let not_null = !addr.is_null();
        not_null.then(|| unsafe { (*addr).sa_family } as i32)
    }

    fn ip(addr: *const c::sockaddr) -> Option<IpAddr> {
        match family(addr) {
            Some(c::AF_INET) => {
                let addr = addr as *const c::sockaddr_in;
                let addr = unsafe { (*addr).sin_addr.s_addr }.to_be_bytes();
                let addr = net::Ipv4Addr::from(addr);
                Some(IpAddr::V4(addr))
            }
            Some(c::AF_INET6) => {
                let addr = addr as *const c::sockaddr_in6;
                let addr = unsafe { (*addr).sin6_addr.s6_addr };
                let addr = net::Ipv6Addr::from(addr);
                Some(IpAddr::V6(addr))
            }
            _ => None,
        }
    }

    fn to_interface(
        base: Option<NonNull<c::ifaddrs>>,
        curr: NonNull<c::ifaddrs>,
    ) -> Option<Interface> {
        let curr = unsafe { curr.as_ref() };
        let addr = NonNull::new(curr.ifa_addr).unwrap();
        let addr = unsafe { addr.as_ref() };

        if is_link(addr) {
            return None;
        }

        let name = unsafe { CStr::from_ptr(curr.ifa_name) };

        let mac = Iter(base)
            .find_map(|link| mac_of(name, link))
            .unwrap_or_default();

        let name = name.to_string_lossy().into_owned();
        let flags = curr.ifa_flags;
        let netmask = ip(curr.ifa_netmask).unwrap_or_else(no_addr);

        let scope_id = (addr.sa_family == c::AF_INET6 as _).then(|| {
            let addr = addr as *const _ as *const c::sockaddr_in6;
            unsafe { (*addr).sin6_scope_id }
        });

        let address = ip(addr).unwrap_or_else(no_addr);

        Some(Interface {
            name,
            flags,
            mac,
            address,
            scope_id,
            netmask,
        })
    }

    fn no_addr() -> IpAddr {
        IpAddr::V4(net::Ipv4Addr::UNSPECIFIED)
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use libc as c;
    use std::ffi::CStr;
    use std::ptr::NonNull;

    pub(crate) fn is_link(addr: *const c::sockaddr) -> bool {
        Some(c::AF_PACKET) == family(addr)
    }

    fn family(addr: *const c::sockaddr) -> Option<i32> {
        let not_null = !addr.is_null();
        not_null.then(|| unsafe { (*addr).sa_family } as i32)
    }

    pub(crate) fn mac_of(
        name: &CStr,
        link: NonNull<c::ifaddrs>,
    ) -> Option<[u8; 6]> {
        let link = unsafe { link.as_ref() };

        if !is_link(link.ifa_addr) {
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

    fn is_link(addr: *const c::sockaddr) -> bool {
        Some(c::AF_LINK) == family(addr)
    }

    fn family(addr: *const c::sockaddr) -> Option<i32> {
        let not_null = !addr.is_null();
        not_null.then(|| unsafe { (*addr).sa_family } as i32)
    }

    fn mac_of(name: &CStr, link: NonNull<c::ifaddrs>) -> Option<[u8; 6]> {
        let link = unsafe { link.as_ref() };

        if !is_link(link.ifa_addr) {
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
        println!("{:?}", ifa);
        assert!(!ifa.name().is_empty());
        assert!(ifa.address().is_ipv4() ^ ifa.scope_id().is_some());
    }
}
