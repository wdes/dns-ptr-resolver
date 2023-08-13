# dns-ptr-resolver

[![dependency status](https://deps.rs/repo/github/wdes/dns-ptr-resolver/status.svg)](https://deps.rs/repo/github/wdes/dns-ptr-resolver)
[![crates.io](https://img.shields.io/crates/v/dns-ptr-resolver.svg)](https://crates.io/crates/dns-ptr-resolver)
[![Build and test rust code](https://github.com/wdes/dns-ptr-resolver/actions/workflows/rust.yml/badge.svg)](https://github.com/wdes/dns-ptr-resolver/actions/workflows/rust.yml)

A Rust program to resolve IP lists to their DNS PTR

It uses the following TCP DNS servers in a round-robin mode:

- "1.1.1.1:53"
- "1.0.0.1:53"
- "8.8.8.8:53"
- "8.8.4.4:53"

And 30 threads.

## Install

```sh
cargo install dns-ptr-resolver
```

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
dns-ptr-resolver ./example/ips-to-resolve.txt 1> ./example/ips-resolved.txt
```
