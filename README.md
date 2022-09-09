netif
=====

List the network interfaces on the system.

Example usage:
```rust
fn main() {
    for ifa in netif::up().unwrap() {
        if !ifa.address().is_loopback() {
            println!("{:?}", ifa);
        }
    }
}
```

license
=======

ISC, see the LICENSE file.
