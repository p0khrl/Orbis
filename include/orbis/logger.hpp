// SPDX-License-Identifier: Apache-2.0
// ORBIS Engine - Logging facility
#pragma once
#include <string_view>

namespace orbis {

enum class LogLevel { Trace, Debug, Info, Warning, Error, Critical };

/// Minimal thread-safe logging facade. Applications may redirect
/// output by providing a sink via Logger::setSink().
class Logger {
public:
    using Sink = void(*)(LogLevel, std::string_view message);

    static void setSink(Sink sink);
    static void log(LogLevel level, std::string_view message);
};

} // namespace orbis
