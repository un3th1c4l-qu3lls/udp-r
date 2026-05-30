# UDP for Rust

A complete, no‑std compatible User Datagram Protocol (UDP) implementation supporting IPv4, IPv6, and modern UDP options (RFC 9868).

## Features

- **IPv4 UDP (RFC 768)** – Pseudo‑header, checksum generation & validation, optional zero checksum.
- **IPv6 UDP (RFC 8200)** – Pseudo‑header with 32‑bit upper‑layer length, mandatory checksum, jumbogram support (UDP length = 0 when payload > 64 KB).
- **Streaming Checksum (RFC 1071)** – Zero‑allocation accumulator, handles odd‑length data with zero padding.
- **UDP Options (RFC 9868)** – TLV format, single‑byte options (EOL, NOP), extended length (255), SAFE/UNSAFE classification.
- **Specific Options** – MDS, MRDS, APC, FRAG (16‑ or 32‑bit ID), REQ/RES, TIME.
- **Surplus Area** – Alignment padding, Option Checksum (OCS) generation and verification.
- **Clean Separation** – Version‑specific modules (`v4`, `v6`), shared `Header`, reusable `Checksum`, independent `option` and `surplus` modules.

## Usage

Add to your `Cargo.toml`:
```toml
[dependencies]
udp = { path = "..." }```
