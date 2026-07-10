// SPDX-License-Identifier: Apache-2.0
#include "orbis/engine.hpp"
#include "orbis/logger.hpp"
#include <atomic>
#include <mutex>

namespace orbis {

struct Engine::Impl {
    std::atomic<ConnectionState> state{ConnectionState::Disconnected};
    std::mutex callbackMutex;
    StateCallback stateCallback;
    Statistics stats{};
    bool initialized = false;

    void setState(ConnectionState s) {
        state.store(s, std::memory_order_release);
        std::lock_guard<std::mutex> lock(callbackMutex);
        if (stateCallback) stateCallback(s);
    }
};

Engine::Engine() : pImpl(std::make_unique<Impl>()) {}
Engine::~Engine() { if (pImpl && pImpl->state != ConnectionState::Disconnected) disconnect(); }
Engine::Engine(Engine&&) noexcept = default;
Engine& Engine::operator=(Engine&&) noexcept = default;

bool Engine::initialize() {
    Logger::log(LogLevel::Info, "ORBIS Engine initializing");
    pImpl->initialized = true;
    return true;
}

bool Engine::loadConfiguration(const Configuration& /*config*/) {
    if (!pImpl->initialized) {
        Logger::log(LogLevel::Error, "loadConfiguration called before initialize()");
        return false;
    }
    // Real implementation: validate and store parsed config, select
    // tunnel plugin based on protocol field. Left as a stub for Phase 2.
    return true;
}

bool Engine::connect() {
    if (!pImpl->initialized) return false;
    pImpl->setState(ConnectionState::Connecting);
    // Phase 2+: delegate to selected ITunnelPlugin implementation.
    pImpl->setState(ConnectionState::Connected);
    return true;
}

void Engine::disconnect() {
    if (pImpl->state == ConnectionState::Disconnected) return;
    pImpl->setState(ConnectionState::Disconnecting);
    pImpl->setState(ConnectionState::Disconnected);
}

void Engine::onStateChanged(StateCallback callback) {
    std::lock_guard<std::mutex> lock(pImpl->callbackMutex);
    pImpl->stateCallback = std::move(callback);
}

Statistics Engine::statistics() const { return pImpl->stats; }
ConnectionState Engine::state() const { return pImpl->state.load(std::memory_order_acquire); }

} // namespace orbis
