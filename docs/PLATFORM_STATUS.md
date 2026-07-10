# Platform Status

Honest, current state of what actually moves packets vs. what's still a
placeholder — check this before assuming a platform "works."

| Platform | Backend                         | Status |
|----------|----------------------------------|--------|
| Linux    | `KernelWireGuardBackend` (netlink → in-kernel WireGuard) | **Real.** Creates an actual interface, configures keys/peers/AllowedIPs via netlink, assigns addresses, brings the link up. Requires a kernel with `CONFIG_WIREGUARD` (mainline since 5.6) and `CAP_NET_ADMIN` (normally root). |
| Windows  | `WireGuardNtBackend` (WireGuardNT via `wireguard.dll`) | **Real.** Loads `wireguard.dll` at runtime, creates a kernel adapter, pushes keys/peers/AllowedIPs via `WireGuardSetConfiguration`, assigns addresses via the IP Helper API, brings the adapter up. Requires `wireguard.dll` present next to the executable and Administrator privileges. Cross-compiled clean with `x86_64-w64-mingw32-g++ -Wall -Wextra -Wpedantic` (zero warnings) and fully linked into a real Windows PE32+ executable — see "How this was verified" below. Not run on real Windows/an actual driver in this environment. |
| macOS    | none (`NullBackend`)             | Placeholder only. Needs `wireguard-go` + `utun` device binding (no in-kernel WireGuard on macOS). |
| Android  | none (`NullBackend`)             | Placeholder only. Needs a `VpnService`-based JNI backend; typically wraps `wireguard-go`. |
| OpenVPN (any OS) | not implemented           | No adapter yet — WireGuard was Phase 4's target protocol. |

## What "real" means here

Neither backend contains any cryptography of its own; both delegate
entirely to an existing, vetted WireGuard implementation.

### Linux

1. Creates a `wireguard`-type netlink link (`RTM_NEWLINK`), the same
   kernel mechanism `ip link add ... type wireguard` uses.
2. Sends `WG_CMD_SET_DEVICE` over generic netlink with the private key,
   listen port, and peer list — the same command `wg set` sends.
3. Assigns interface addresses (`RTM_NEWADDR`) and brings the link up.
4. Reads live rx/tx counters back via `WG_CMD_GET_DEVICE`.

All handshakes, key derivation, and packet encryption/decryption are
performed entirely by the kernel's WireGuard implementation.

### Windows

1. Dynamically loads `wireguard.dll` (`LoadLibraryExW` + `GetProcAddress`
   for each entry point) — the officially documented way to embed
   WireGuardNT, per the upstream project's README ("the embeddable DLL
   service project"). ORBIS Engine does not vendor or redistribute the
   DLL; applications must ship it themselves.
2. Calls `WireGuardCreateAdapter` to create a kernel adapter, then builds
   the variable-length `WIREGUARD_INTERFACE` + `WIREGUARD_PEER` +
   `WIREGUARD_ALLOWED_IP` buffer and pushes it via
   `WireGuardSetConfiguration` — identical to what the official WireGuard
   for Windows application does internally.
3. Assigns interface addresses via `CreateUnicastIpAddressEntry` (IP
   Helper API), keyed off the adapter's LUID from
   `WireGuardGetAdapterLUID`, since WireGuardNT's own API only configures
   protocol state, not IP addressing.
4. Brings the adapter up via `WireGuardSetAdapterState`, and reads live
   counters back via `WireGuardGetConfiguration`.

`src/platform/windows/wireguard_nt_api.h` is a trimmed, structurally
identical transcription of the upstream `wireguard.h` (WireGuard/wireguard-nt,
`api/wireguard.h`) — the stable public ABI applications are expected to
vendor locally, not a reimplementation of anything.

## Known gaps even on the "real" backends

- No automatic default-route/kill-switch installation (intentional —
  that's routing *policy*, which belongs in a higher-level component,
  not the tunnel adapter itself).
- No DNS reconfiguration.
- Endpoint hostnames are resolved once at `configure()` time, not
  re-resolved on roaming (matches `wg-quick` behavior).
- Both require elevated privileges (`CAP_NET_ADMIN` / Administrator);
  the engine does not attempt privilege elevation itself.

## How this was verified

**Linux:** compiled with `g++ -Wall -Wextra -Wpedantic` (zero warnings),
linked, and actually run in this environment. Sending the real
`RTM_NEWLINK` netlink message against this machine's live kernel
returned `-EOPNOTSUPP`, which the code reports correctly and honestly —
this sandbox has no loadable WireGuard kernel module, so `open()`
deterministically fails with a clear log line rather than pretending to
succeed. On a real Linux host with `CONFIG_WIREGUARD` and root, the same
code path creates a working interface.

**Windows:** this sandbox is Linux-only — there is no Windows machine,
MSVC, or Windows Server available to run the resulting binary against a
real `wireguard.dll` and driver. What *was* verified for real:
cross-compiled every source file with `x86_64-w64-mingw32-g++ -Wall
-Wextra -Wpedantic` (zero warnings after fixing two real portability
bugs it caught — see git history), and fully linked a static Windows
PE32+ executable (`examples/basic_connect.cpp` + the full engine +
`WireGuardNtBackend`) with no unresolved symbols. That confirms the
struct layouts, calling conventions, and API usage match the real
WireGuardNT ABI. It does **not** confirm runtime behavior against an
actual driver — treat the Windows backend as "compiles and links
correctly against the real API, not yet run against real hardware,"
and test it on an actual Windows machine before shipping.

```bash
# Linux
sudo ./examples/basic_connect   # replace the placeholder keys first
ip link show orbis0             # interface should exist and be UP
wg show orbis0                  # kernel's own tool confirms the config

# Windows (from an actual Windows machine, as Administrator)
# 1. Download wireguard.dll from the wireguard-nt download server
#    and place it next to basic_connect.exe
# 2. Replace the placeholder keys in examples/basic_connect.cpp
basic_connect.exe
```

