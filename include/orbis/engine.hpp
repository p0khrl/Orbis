// SPDX-License-Identifier: Apache-2.0
// ORBIS Engine - Public API
#pragma once

#include <memory>
#include <string>
#include <functional>
#include <cstdint>

namespace orbis {

/// Connection lifecycle states.
enum class ConnectionState {
    Disconnected,
    Connecting,
    Connected,
    Reconnecting,
    Disconnecting,
    Error
};

/// Aggregate traffic/session statistics.
struct Statistics {
    std::uint64_t bytesSent = 0;
    std::uint64_t bytesReceived = 0;
    std::uint64_t durationSeconds = 0;
};

/// Callback invoked on connection state transitions.
using StateCallback = std::function<void(ConnectionState)>;

/// Opaque configuration handle (loaded from JSON/file/string).
class Configuration;

/// Engine is the primary entry point of ORBIS Engine.
/// Owns session/connection lifecycle and protocol plugins.
/// Not copyable; movable. Thread-safe public methods.
class Engine {
public:
    Engine();
    ~Engine();

    Engine(const Engine&) = delete;
    Engine& operator=(const Engine&) = delete;
    Engine(Engine&&) noexcept;
    Engine& operator=(Engine&&) noexcept;

    /// Initializes internal subsystems (logger, thread pool, RNG).
    /// Must be called once before any other method.
    bool initialize();

    /// Loads engine + protocol configuration.
    bool loadConfiguration(const Configuration& config);

    /// Establishes a VPN session using the active protocol plugin.
    bool connect();

    /// Gracefully tears down the active session.
    void disconnect();

    /// Registers a callback for connection state changes.
    void onStateChanged(StateCallback callback);

    /// Returns current traffic/session statistics.
    Statistics statistics() const;

    ConnectionState state() const;

private:
    struct Impl;
    std::unique_ptr<Impl> pImpl;
};

} // namespace orbis
