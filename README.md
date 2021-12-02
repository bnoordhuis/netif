netif
=====

List the network interfaces on the system.

Example usage:
```rust
for ifa in netif::all() {
    if !ifa.address().is_loopback() {
        println!("{:?}", ifa);
    }
}
```

license
=======

ISC, see the LICENSE file.
