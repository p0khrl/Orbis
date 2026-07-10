# ORBIS Engine

A cross-platform VPN engine written in C++20.

ORBIS is a library for applications that need VPN functionality. It provides the core engine for managing VPN connections while using native platform implementations instead of implementing cryptography itself. It is **not** a standalone VPN client.

## Current status

Linux uses the kernel WireGuard implementation through Netlink.

Windows uses WireGuardNT through `wireguard.dll`.

macOS, Android, and iOS are not implemented yet.

See `docs/PLATFORM_STATUS.md` for the current implementation status.

## Build

```bash
cmake -S . -B build
cmake --build build
ctest --test-dir build
```

## Example

Build the example:

```bash
cmake --build build --target basic_connect
```

Generate a WireGuard key pair:

```bash
wg genkey
wg pubkey
```

Edit `examples/basic_connect.cpp` with your configuration, then run:

```bash
sudo ./build/examples/basic_connect
```

## Documentation

* `docs/ARCHITECTURE.md` — engine architecture
* `docs/PLATFORM_STATUS.md` — platform support

## License

Apache-2.0
