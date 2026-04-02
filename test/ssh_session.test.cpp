#include <catch2/catch_test_macros.hpp>
#include <ssh_connection/ssh_connection.h>

using namespace ohtoai::ssh;

// ──────────────────────────────────────────────────────────────────────────────
// ssh_session::generate_id()
// ──────────────────────────────────────────────────────────────────────────────
TEST_CASE("ssh_session::generate_id with username", "[ssh_session]") {
    auto id = ssh_session::generate_id("example.com", 22, "alice");
    REQUIRE(id == "alice@example.com:22");
}

TEST_CASE("ssh_session::generate_id without username", "[ssh_session]") {
    auto id = ssh_session::generate_id("example.com", 22, "");
    REQUIRE(id == "example.com:22");
}

TEST_CASE("ssh_session::generate_id with non-default port", "[ssh_session]") {
    auto id = ssh_session::generate_id("192.168.1.1", 2222, "bob");
    REQUIRE(id == "bob@192.168.1.1:2222");
}

TEST_CASE("ssh_session::generate_id with custom suffix", "[ssh_session]") {
    auto id = ssh_session::generate_id("host.local", 22, "carol", "/extra");
    REQUIRE(id == "carol@host.local:22/extra");
}

TEST_CASE("ssh_session::generate_id without username but with custom suffix", "[ssh_session]") {
    auto id = ssh_session::generate_id("host.local", 22, "", "/extra");
    REQUIRE(id == "host.local:22/extra");
}

TEST_CASE("ssh_session::generate_id distinguishes different users on the same host", "[ssh_session]") {
    auto id1 = ssh_session::generate_id("host.local", 22, "alice");
    auto id2 = ssh_session::generate_id("host.local", 22, "bob");
    REQUIRE(id1 != id2);
}

TEST_CASE("ssh_session::generate_id distinguishes different ports on the same host", "[ssh_session]") {
    auto id1 = ssh_session::generate_id("host.local", 22, "alice");
    auto id2 = ssh_session::generate_id("host.local", 2222, "alice");
    REQUIRE(id1 != id2);
}

// ──────────────────────────────────────────────────────────────────────────────
// ssh_pty_connection_manager – state management (no network required)
// ──────────────────────────────────────────────────────────────────────────────
TEST_CASE("ssh_pty_connection_manager default max_channel_in_session is 3", "[connection_manager]") {
    auto &mgr = ssh_pty_connection_manager::get_instance();
    REQUIRE(mgr.get_max_channel_in_session() == 3);
}

TEST_CASE("ssh_pty_connection_manager set_max_channel_in_session", "[connection_manager]") {
    auto &mgr = ssh_pty_connection_manager::get_instance();
    mgr.set_max_channel_in_session(5);
    REQUIRE(mgr.get_max_channel_in_session() == 5);
    // restore default
    mgr.set_max_channel_in_session(3);
    REQUIRE(mgr.get_max_channel_in_session() == 3);
}

TEST_CASE("ssh_pty_connection_manager set_max_channel_in_session to zero (unlimited)", "[connection_manager]") {
    auto &mgr = ssh_pty_connection_manager::get_instance();
    mgr.set_max_channel_in_session(0);
    REQUIRE(mgr.get_max_channel_in_session() == 0);
    // restore default
    mgr.set_max_channel_in_session(3);
}

TEST_CASE("ssh_pty_connection_manager get_channel returns nullptr for unknown channel_id", "[connection_manager]") {
    auto &mgr = ssh_pty_connection_manager::get_instance();
    auto ch = mgr.get_channel("nonexistent-channel-id-xyz");
    REQUIRE(ch == nullptr);
}

TEST_CASE("ssh_pty_connection_manager close_channel on unknown id is safe", "[connection_manager]") {
    auto &mgr = ssh_pty_connection_manager::get_instance();
    // Should not throw or crash
    REQUIRE_NOTHROW(mgr.close_channel("nonexistent-channel-id-xyz"));
}

TEST_CASE("ssh_pty_connection_manager get_channel_count for unknown session_id is zero", "[connection_manager]") {
    auto &mgr = ssh_pty_connection_manager::get_instance();
    auto count = mgr.get_channel_count("nonexistent@host:22");
    REQUIRE(count == 0);
}
