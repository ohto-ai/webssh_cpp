#include <catch2/catch_test_macros.hpp>
#include <ssh_connection/ssh_connection.h>
#include <cstdlib>
#include <string>

// ──────────────────────────────────────────────────────────────────────────────
// Helpers – read environment variables for the test SSH server.
//
// Set these variables to run the integration tests:
//   TEST_SSH_HOST  – hostname or IP of the SSH server (required)
//   TEST_SSH_PORT  – port number                      (default: 22)
//   TEST_SSH_USER  – username                         (required)
//   TEST_SSH_PASS  – password                         (required)
//
// When TEST_SSH_HOST is not set the tests are skipped.
// ──────────────────────────────────────────────────────────────────────────────
namespace {

struct SshConfig {
    std::string host;
    int         port = 22;
    std::string username;
    std::string password;
    bool        available = false;
};

SshConfig get_ssh_config() {
    SshConfig cfg;
    const char *host = std::getenv("TEST_SSH_HOST");
    if (!host || std::string(host).empty()) {
        return cfg;   // available == false → tests will be skipped
    }
    cfg.host = host;

    const char *port = std::getenv("TEST_SSH_PORT");
    if (port && *port) {
        try { cfg.port = std::stoi(port); } catch (...) { cfg.port = 22; }
    }

    const char *user = std::getenv("TEST_SSH_USER");
    cfg.username = (user && *user) ? user : "";

    const char *pass = std::getenv("TEST_SSH_PASS");
    cfg.password = (pass && *pass) ? pass : "";

    cfg.available = !cfg.host.empty() && !cfg.username.empty() && !cfg.password.empty();
    return cfg;
}

} // anonymous namespace

using namespace ohtoai::ssh;

// ──────────────────────────────────────────────────────────────────────────────
// Connection and authentication tests
// ──────────────────────────────────────────────────────────────────────────────
TEST_CASE("SSH session connects and authenticates successfully", "[ssh_integration]") {
    auto cfg = get_ssh_config();
    if (!cfg.available) {
        WARN("Skipping SSH integration tests: TEST_SSH_HOST / TEST_SSH_USER / TEST_SSH_PASS not set");
        return;
    }

    ssh_session session;
    REQUIRE_NOTHROW(session.connect(cfg.host, cfg.port));
    REQUIRE_NOTHROW(session.authenticate(cfg.username, cfg.password));
    REQUIRE_NOTHROW(session.disconnect());
}

TEST_CASE("SSH session rejects wrong password", "[ssh_integration]") {
    auto cfg = get_ssh_config();
    if (!cfg.available) {
        WARN("Skipping SSH integration tests: TEST_SSH_HOST / TEST_SSH_USER / TEST_SSH_PASS not set");
        return;
    }

    ssh_session session;
    REQUIRE_NOTHROW(session.connect(cfg.host, cfg.port));
    REQUIRE_THROWS(session.authenticate(cfg.username, "__definitely_wrong_password__"));
}

TEST_CASE("SSH session fails to connect to a bad host", "[ssh_integration]") {
    auto cfg = get_ssh_config();
    if (!cfg.available) {
        WARN("Skipping SSH integration tests: TEST_SSH_HOST / TEST_SSH_USER / TEST_SSH_PASS not set");
        return;
    }

    ssh_session session;
    // Port 1 is almost never open; expect a connection failure.
    REQUIRE_THROWS(session.connect(cfg.host, 1));
}

// ──────────────────────────────────────────────────────────────────────────────
// Channel lifecycle tests
// ──────────────────────────────────────────────────────────────────────────────
TEST_CASE("SSH channel can be opened and closed", "[ssh_integration]") {
    auto cfg = get_ssh_config();
    if (!cfg.available) {
        WARN("Skipping SSH integration tests: TEST_SSH_HOST / TEST_SSH_USER / TEST_SSH_PASS not set");
        return;
    }

    ssh_session session;
    session.connect(cfg.host, cfg.port);
    session.authenticate(cfg.username, cfg.password);

    ssh_channel_ptr channel;
    REQUIRE_NOTHROW(channel = session.open_channel());
    REQUIRE(channel != nullptr);
    REQUIRE(channel->is_open());

    REQUIRE_NOTHROW(channel->close());
    REQUIRE_FALSE(channel->is_open());
}

TEST_CASE("SSH channel supports PTY request and shell", "[ssh_integration]") {
    auto cfg = get_ssh_config();
    if (!cfg.available) {
        WARN("Skipping SSH integration tests: TEST_SSH_HOST / TEST_SSH_USER / TEST_SSH_PASS not set");
        return;
    }

    ssh_session session;
    session.connect(cfg.host, cfg.port);
    session.authenticate(cfg.username, cfg.password);

    auto channel = session.open_channel();
    REQUIRE(channel != nullptr);

    REQUIRE_NOTHROW(channel->request_pty("xterm-256color"));
    REQUIRE_NOTHROW(channel->shell());
    REQUIRE(channel->is_open());

    REQUIRE_NOTHROW(channel->close());
}

TEST_CASE("SSH channel supports PTY resize", "[ssh_integration]") {
    auto cfg = get_ssh_config();
    if (!cfg.available) {
        WARN("Skipping SSH integration tests: TEST_SSH_HOST / TEST_SSH_USER / TEST_SSH_PASS not set");
        return;
    }

    ssh_session session;
    session.connect(cfg.host, cfg.port);
    session.authenticate(cfg.username, cfg.password);

    auto channel = session.open_channel();
    channel->request_pty("xterm-256color");
    channel->shell();

    REQUIRE_NOTHROW(channel->resize_pty(120, 40));

    channel->close();
}

// ──────────────────────────────────────────────────────────────────────────────
// Connection manager integration tests
// ──────────────────────────────────────────────────────────────────────────────
TEST_CASE("Connection manager creates a channel via get_channel", "[ssh_integration]") {
    auto cfg = get_ssh_config();
    if (!cfg.available) {
        WARN("Skipping SSH integration tests: TEST_SSH_HOST / TEST_SSH_USER / TEST_SSH_PASS not set");
        return;
    }

    auto &mgr = ssh_pty_connection_manager::get_instance();
    size_t sessions_before = mgr.get_session_count();
    size_t channels_before = mgr.get_channel_count();

    ssh_channel_ptr ch;
    REQUIRE_NOTHROW(ch = mgr.get_channel(cfg.host, cfg.port, cfg.username, cfg.password));
    REQUIRE(ch != nullptr);

    REQUIRE(mgr.get_session_count() > sessions_before);
    REQUIRE(mgr.get_channel_count() > channels_before);
    REQUIRE(mgr.get_channel_alive_count() >= 1);

    // Retrieve the same channel by ID
    auto ch2 = mgr.get_channel(ch->id);
    REQUIRE(ch2 != nullptr);
    REQUIRE(ch2->id == ch->id);

    mgr.close_channel(ch->id);
    // After closing the last channel in a session the session itself is removed.
    REQUIRE(mgr.get_channel_alive_count() == channels_before);
}

TEST_CASE("Connection manager reuses session for multiple channels", "[ssh_integration]") {
    auto cfg = get_ssh_config();
    if (!cfg.available) {
        WARN("Skipping SSH integration tests: TEST_SSH_HOST / TEST_SSH_USER / TEST_SSH_PASS not set");
        return;
    }

    auto &mgr = ssh_pty_connection_manager::get_instance();
    // Allow at least 2 channels per session for this test
    mgr.set_max_channel_in_session(5);

    size_t sessions_before = mgr.get_session_count();

    auto ch1 = mgr.get_channel(cfg.host, cfg.port, cfg.username, cfg.password);
    auto ch2 = mgr.get_channel(cfg.host, cfg.port, cfg.username, cfg.password);

    REQUIRE(ch1 != nullptr);
    REQUIRE(ch2 != nullptr);
    REQUIRE(ch1->id != ch2->id);

    // Both channels should share the same session → session count unchanged.
    REQUIRE(mgr.get_session_count() == sessions_before + 1);

    mgr.close_channel(ch1->id);
    mgr.close_channel(ch2->id);

    // restore default
    mgr.set_max_channel_in_session(3);
}

TEST_CASE("Connection manager opens a new session when max channels reached", "[ssh_integration]") {
    auto cfg = get_ssh_config();
    if (!cfg.available) {
        WARN("Skipping SSH integration tests: TEST_SSH_HOST / TEST_SSH_USER / TEST_SSH_PASS not set");
        return;
    }

    auto &mgr = ssh_pty_connection_manager::get_instance();
    mgr.set_max_channel_in_session(1); // only 1 channel per session

    size_t sessions_before = mgr.get_session_count();

    auto ch1 = mgr.get_channel(cfg.host, cfg.port, cfg.username, cfg.password);
    auto ch2 = mgr.get_channel(cfg.host, cfg.port, cfg.username, cfg.password);

    REQUIRE(ch1 != nullptr);
    REQUIRE(ch2 != nullptr);
    // With max=1, a second channel forces a second session.
    REQUIRE(mgr.get_session_count() >= sessions_before + 2);

    mgr.close_channel(ch1->id);
    mgr.close_channel(ch2->id);

    // restore default
    mgr.set_max_channel_in_session(3);
}
