/* SPDX-License-Identifier: GPL-2.0 OR MIT
 *
 * Vendored from the official WireGuardNT embedding API, distributed by
 * WireGuard LLC for use by third-party applications embedding
 * WireGuardNT via wireguard.dll. Source: WireGuard/wireguard-nt,
 * api/wireguard.h (mirror: https://github.com/WireGuard/wireguard-nt,
 * canonical: https://git.zx2c4.com/wireguard-nt). Reproduced here
 * because it is the stable public ABI applications are expected to
 * vendor locally when embedding WireGuardNT — this project does not
 * modify or reimplement any of it. Trimmed to the subset ORBIS Engine
 * actually calls; the full header also declares adapter-creation and
 * logging entry points not currently used here.
 */
#pragma once
#ifdef _WIN32

#include <winsock2.h>
#include <windows.h>
#include <ipexport.h>
#include <ifdef.h>
#include <ws2ipdef.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef ALIGNED
#if defined(_MSC_VER)
#define ALIGNED(n) __declspec(align(n))
#elif defined(__GNUC__)
#define ALIGNED(n) __attribute__((aligned(n)))
#else
#error "Unable to define ALIGNED"
#endif
#endif

typedef struct _WIREGUARD_ADAPTER *WIREGUARD_ADAPTER_HANDLE;

typedef WIREGUARD_ADAPTER_HANDLE(WINAPI *WIREGUARD_CREATE_ADAPTER_FUNC)(
    LPCWSTR Name, LPCWSTR TunnelType, const GUID *RequestedGUID);

typedef WIREGUARD_ADAPTER_HANDLE(WINAPI *WIREGUARD_OPEN_ADAPTER_FUNC)(LPCWSTR Name);

typedef VOID(WINAPI *WIREGUARD_CLOSE_ADAPTER_FUNC)(WIREGUARD_ADAPTER_HANDLE Adapter);

typedef BOOL(WINAPI *WIREGUARD_DELETE_DRIVER_FUNC)(VOID);

typedef VOID(WINAPI *WIREGUARD_GET_ADAPTER_LUID_FUNC)(WIREGUARD_ADAPTER_HANDLE Adapter, NET_LUID *Luid);

typedef DWORD(WINAPI *WIREGUARD_GET_RUNNING_DRIVER_VERSION_FUNC)(VOID);

typedef enum {
    WIREGUARD_ADAPTER_STATE_DOWN,
    WIREGUARD_ADAPTER_STATE_UP,
} WIREGUARD_ADAPTER_STATE;

typedef BOOL(WINAPI *WIREGUARD_SET_ADAPTER_STATE_FUNC)(
    WIREGUARD_ADAPTER_HANDLE Adapter, WIREGUARD_ADAPTER_STATE State);

typedef BOOL(WINAPI *WIREGUARD_GET_ADAPTER_STATE_FUNC)(
    WIREGUARD_ADAPTER_HANDLE Adapter, WIREGUARD_ADAPTER_STATE *State);

#define WIREGUARD_KEY_LENGTH 32

typedef enum {
    WIREGUARD_ALLOWED_IP_REMOVE = 1 << 0
} WIREGUARD_ALLOWED_IP_FLAG;

#pragma pack(push, 8)
typedef struct ALIGNED(8) _WIREGUARD_ALLOWED_IP {
    union {
        IN_ADDR V4;
        IN6_ADDR V6;
    } Address;
    ADDRESS_FAMILY AddressFamily;
    BYTE Cidr;
    WIREGUARD_ALLOWED_IP_FLAG Flags;
} WIREGUARD_ALLOWED_IP;

typedef enum {
    WIREGUARD_PEER_HAS_PUBLIC_KEY = 1 << 0,
    WIREGUARD_PEER_HAS_PRESHARED_KEY = 1 << 1,
    WIREGUARD_PEER_HAS_PERSISTENT_KEEPALIVE = 1 << 2,
    WIREGUARD_PEER_HAS_ENDPOINT = 1 << 3,
    WIREGUARD_PEER_REPLACE_ALLOWED_IPS = 1 << 5,
    WIREGUARD_PEER_REMOVE = 1 << 6,
    WIREGUARD_PEER_UPDATE_ONLY = 1 << 7
} WIREGUARD_PEER_FLAG;

typedef struct ALIGNED(8) _WIREGUARD_PEER {
    WIREGUARD_PEER_FLAG Flags;
    DWORD Reserved;
    BYTE PublicKey[WIREGUARD_KEY_LENGTH];
    BYTE PresharedKey[WIREGUARD_KEY_LENGTH];
    WORD PersistentKeepalive;
    SOCKADDR_INET Endpoint;
    DWORD64 TxBytes;
    DWORD64 RxBytes;
    DWORD64 LastHandshake;
    DWORD AllowedIPsCount;
} WIREGUARD_PEER;

typedef enum {
    WIREGUARD_INTERFACE_HAS_PUBLIC_KEY = 1 << 0,
    WIREGUARD_INTERFACE_HAS_PRIVATE_KEY = 1 << 1,
    WIREGUARD_INTERFACE_HAS_LISTEN_PORT = 1 << 2,
    WIREGUARD_INTERFACE_REPLACE_PEERS = 1 << 3
} WIREGUARD_INTERFACE_FLAG;

typedef struct ALIGNED(8) _WIREGUARD_INTERFACE {
    WIREGUARD_INTERFACE_FLAG Flags;
    WORD ListenPort;
    BYTE PrivateKey[WIREGUARD_KEY_LENGTH];
    BYTE PublicKey[WIREGUARD_KEY_LENGTH];
    DWORD PeersCount;
} WIREGUARD_INTERFACE;
#pragma pack(pop)

typedef BOOL(WINAPI *WIREGUARD_SET_CONFIGURATION_FUNC)(
    WIREGUARD_ADAPTER_HANDLE Adapter, const WIREGUARD_INTERFACE *Config, DWORD Bytes);

typedef BOOL(WINAPI *WIREGUARD_GET_CONFIGURATION_FUNC)(
    WIREGUARD_ADAPTER_HANDLE Adapter, WIREGUARD_INTERFACE *Config, DWORD *Bytes);

#ifdef __cplusplus
}
#endif

#endif // _WIN32
