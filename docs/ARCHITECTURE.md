# ORBIS Engine — Architecture (Phase 1)

## Layout

- `include/orbis/` — public headers (stable API surface consumers link against)
- `src/core/` — engine lifecycle, logging, session/connection management
- `src/network/` — TCP/UDP/DNS/routing/socket abstractions (Phase 3)
- `src/tunnel/` — protocol plugin interface + WireGuard/OpenVPN adapters (Phase 4)
- `src/security/` — crypto interfaces wrapping vetted libraries only (Phase 4)
- `src/platform/` — per-OS backends behind common interfaces (Phase 5)
- `src/util/` — thread pool, JSON config, error handling helpers
- `tests/` — GoogleTest unit/integration tests
- `examples/` — minimal consumer programs
- `tools/` — dev scripts (formatting, static analysis)
- `cmake/` — shared CMake modules
- `.github/workflows/` — CI (build/test/format/lint)

## Design decisions (Phase 1)

- **Pimpl idiom** on `Engine` to keep the public ABI stable as internals evolve.
- **Callback-based state changes** rather than polling, for responsive UI integration.
- Engine currently contains **stub connect logic**; real tunnel dispatch arrives in
  Phase 4 once the plugin interface (`ITunnelPlugin`) is defined.
- No cryptography is implemented yet. Security module will wrap **libsodium /
  OpenSSL / wireguard-tools**, never custom crypto.

## Next phases

1. Configuration + JSON loading, error handling utilities
2. Session/Connection managers, event system
3. Network layer (sockets, DNS, routing)
4. Tunnel plugin interface + WireGuard adapter (via wireguard-go or userspace lib)
5. Platform backends (routing table / kill switch per OS)
6. OpenVPN adapter, docs, CI hardening
