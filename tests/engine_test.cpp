// SPDX-License-Identifier: Apache-2.0
#include <gtest/gtest.h>
#include "orbis/engine.hpp"

TEST(EngineTest, InitializeSucceeds) {
    orbis::Engine engine;
    EXPECT_TRUE(engine.initialize());
}

TEST(EngineTest, ConnectRequiresInitialize) {
    orbis::Engine engine;
    // connect() before initialize() should fail gracefully.
    EXPECT_FALSE(engine.connect());
}

TEST(EngineTest, ConnectDisconnectTransitionsState) {
    orbis::Engine engine;
    ASSERT_TRUE(engine.initialize());
    EXPECT_TRUE(engine.connect());
    EXPECT_EQ(engine.state(), orbis::ConnectionState::Connected);
    engine.disconnect();
    EXPECT_EQ(engine.state(), orbis::ConnectionState::Disconnected);
}
