# dns-ptr-resolver

A Rust program to resolve IP lists to their DNS PTR

It uses the `1.1.1.1:53` DNS server.

## Example input

```text
192.0.2.255
::1
1.1.1.1
1.0.0.1
2606:4700:4700::1111
2606:4700:4700::1001
8.8.8.8
8.8.4.4
9.9.9.9
```

## Example output

```text
1.0.0.1 # one.one.one.one.
::1
2606:4700:4700::1111 # one.one.one.one.
1.1.1.1 # one.one.one.one.
9.9.9.9 # dns9.quad9.net.
8.8.4.4 # dns.google.
2606:4700:4700::1001 # one.one.one.one.
8.8.8.8 # dns.google.
192.0.2.255
```

## Rebuild example

```sh
cargo run --release ./example/ips-to-resolve.txt > ./example/ips-resolved.txt
```
