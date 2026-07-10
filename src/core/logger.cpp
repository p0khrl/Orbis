// SPDX-License-Identifier: Apache-2.0
#include "orbis/logger.hpp"
#include <cstdio>
#include <mutex>

namespace orbis {
namespace {
std::mutex g_sinkMutex;
Logger::Sink g_sink = nullptr;

const char* levelName(LogLevel level) {
    switch (level) {
        case LogLevel::Trace: return "TRACE";
        case LogLevel::Debug: return "DEBUG";
        case LogLevel::Info: return "INFO";
        case LogLevel::Warning: return "WARN";
        case LogLevel::Error: return "ERROR";
        case LogLevel::Critical: return "CRIT";
    }
    return "?";
}
} // namespace

void Logger::setSink(Sink sink) {
    std::lock_guard<std::mutex> lock(g_sinkMutex);
    g_sink = sink;
}

void Logger::log(LogLevel level, std::string_view message) {
    std::lock_guard<std::mutex> lock(g_sinkMutex);
    if (g_sink) {
        g_sink(level, message);
    } else {
        std::fprintf(stderr, "[orbis][%s] %.*s\n", levelName(level),
                     static_cast<int>(message.size()), message.data());
    }
}

} // namespace orbis
