# ORBIS Engine

A modular, cross-platform VPN engine (library) for integration into desktop,
mobile, server, and embedded applications. Not a standalone VPN app.

Status: **Phase 5.** WireGuard has real backends on Linux (netlink → kernel
WireGuard) and Windows (WireGuardNT via `wireguard.dll`) — no custom crypto
in either. macOS/Android are still placeholders. See
[docs/PLATFORM_STATUS.md](docs/PLATFORM_STATUS.md) for exactly what works,
what was actually verified, and how.

## Build

```bash
cmake -S . -B build
cmake --build build
ctest --test-dir build
```

## Try a real tunnel (Linux, root)

```bash
# Edit examples/basic_connect.cpp with real keys from `wg genkey`/`wg pubkey`
cmake --build build --target basic_connect
sudo ./build/examples/basic_connect
```

## Layout

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## License

Apache-2.0
