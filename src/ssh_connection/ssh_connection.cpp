#include "ssh_connection.h"

#include <memory>
#include <libssh2.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdexcept>
#include <spdlog/spdlog.h>
#include <spdlog/fmt/fmt.h>
#include <unistd.h>

struct DebugInfo {
    const char *file = nullptr;
    const char *func_name = nullptr;
    int line = 0;
};

// Internal implementation for functions with non-void return type
template <typename Result, typename Func, typename... Args>
auto wrapSSHFunctionImpl(const DebugInfo &dbg_info, LIBSSH2_SESSION* session, Func func, Args&&... args) -> decltype(func(std::forward<Args>(args)...)){
    if constexpr (std::is_same_v<Result, void>) {
        return func(std::forward<Args>(args)...);
    }
    else {
        Result rc {};
        while (true) {
            rc = func(std::forward<Args>(args)...);
            if (rc > 0) {
                return rc;
            }
            else if (rc != LIBSSH2_ERROR_EAGAIN) {
                char *error_msg = nullptr;
                libssh2_session_last_error(session, &error_msg, nullptr, 0);
                throw std::runtime_error(fmt::format("{}:{} ({}) {}", dbg_info.file, dbg_info.line, rc, error_msg));
            }
        }
        return rc;
    }
}

#define WRAP_SSH_FUNCTION(session, func, ...) wrapSSHFunctionImpl<decltype(func(__VA_ARGS__)), decltype(func), decltype(__VA_ARGS__)>({__FILE__, __func__, __LINE__}, session, func, __VA_ARGS__)

ohtoai::ssh::detail::ssh_channel::ssh_channel():
    id(std::to_string(reinterpret_cast<uintptr_t>(this))) {
    channel = nullptr;
    session = nullptr;
}

ohtoai::ssh::detail::ssh_channel::~ssh_channel() {
    close();
    spdlog::debug("[{}] Channel closed", id);
}

void ohtoai::ssh::detail::ssh_channel::reserve_buffer(size_t size) {
    buffer.reserve(size);
}

const ohtoai::mini_buffer& ohtoai::ssh::detail::ssh_channel::get_buffer() {
    return buffer;
}

bool ohtoai::ssh::detail::ssh_channel::is_open() {
    return channel != nullptr && libssh2_channel_eof(channel) == 0;
}

long ohtoai::ssh::detail::ssh_channel::read() {
    if (channel == nullptr) {
        throw std::runtime_error(fmt::format("[{}] Channel is not opened", id));
    }
    long rc = libssh2_channel_read(channel, buffer.data, buffer.capacity);

    if (rc == LIBSSH2_ERROR_EAGAIN) {
        rc = 0;
    }

    if (rc < 0) {
        char *error_msg = nullptr;
        libssh2_session_last_error(session->session, &error_msg, nullptr, 0);
        throw std::runtime_error(fmt::format("[{}]({}) <{}> {}", id, __LINE__, rc, error_msg));
    }
    buffer.resize(rc);

    if (rc >0) {
        spdlog::debug("[{}] Read {} bytes", id, rc);
    }
    return rc;
}

void ohtoai::ssh::detail::ssh_channel::write(const byte* data, size_t size) {
    if (channel == nullptr) {
        throw std::runtime_error(fmt::format("[{}] Channel is not opened", id));
    }
    ssize_t rc = libssh2_channel_write(channel, data, size);
    if (rc < 0 && rc != LIBSSH2_ERROR_EAGAIN) {
        char *error_msg = nullptr;
        libssh2_session_last_error(session->session, &error_msg, nullptr, 0);
        throw std::runtime_error(fmt::format("[{}]({}) <{}> {}", id, __LINE__, rc, error_msg));
    }
    spdlog::debug("[{}] Wrote {} bytes", id, rc);
}

void ohtoai::ssh::detail::ssh_channel::write(const std::string &data) {
    write(reinterpret_cast<const byte*>(data.data()), data.size());
}

void ohtoai::ssh::detail::ssh_channel::set_env(const std::string &name, const std::string &value) {
    if (channel == nullptr) {
        throw std::runtime_error(fmt::format("[{}] Channel is not opened", id));
    }
    while (int rc = libssh2_channel_setenv(channel, name.c_str(), value.c_str())) {
        if (rc != LIBSSH2_ERROR_EAGAIN) {
            char *error_msg = nullptr;
            libssh2_session_last_error(session->session, &error_msg, nullptr, 0);
            throw std::runtime_error(fmt::format("[{}]({}) <{}> {}", id, __LINE__, rc, error_msg));
        }
        session->wait_socket();
    }
    spdlog::debug("[{}] Env set {}={}", id, name, value);
}

void ohtoai::ssh::detail::ssh_channel::shell() {
    if (channel == nullptr) {
        throw std::runtime_error(fmt::format("[{}] Channel is not opened", id));
    }
    while (int rc = libssh2_channel_shell(channel)) {
        if (rc != LIBSSH2_ERROR_EAGAIN) {
            char *error_msg = nullptr;
            libssh2_session_last_error(session->session, &error_msg, nullptr, 0);
            throw std::runtime_error(fmt::format("[{}]({}) <{}> {}", id, __LINE__, rc, error_msg));
        }
        session->wait_socket();
    }
    spdlog::debug("[{}] Shell requested", id);
}

void ohtoai::ssh::detail::ssh_channel::request_pty(const std::string &pty_type) {
    if (channel == nullptr) {
        throw std::runtime_error(fmt::format("[{}] Channel is not opened", id));
    }

    while (int rc = libssh2_channel_request_pty(channel, pty_type.c_str())) {
        if (rc != LIBSSH2_ERROR_EAGAIN) {
            char *error_msg = nullptr;
            libssh2_session_last_error(session->session, &error_msg, nullptr, 0);
            throw std::runtime_error(fmt::format("[{}]({}) <{}> {}", id, __LINE__, rc, error_msg));
        }
        session->wait_socket();
    }
    spdlog::debug("[{}] Pty requested {}", id, pty_type);
}

void ohtoai::ssh::detail::ssh_channel::resize_pty(int width, int height) {
    if (channel == nullptr) {
        throw std::runtime_error(fmt::format("[{}] Channel is not opened", id));
    }
    spdlog::debug("[{}] Pty resized {}x{}", id, width, height);
    while (int rc = libssh2_channel_request_pty_size(channel, width, height)) {
        if (rc != LIBSSH2_ERROR_EAGAIN) {
            char *error_msg = nullptr;
            libssh2_session_last_error(session->session, &error_msg, nullptr, 0);
            throw std::runtime_error(fmt::format("[{}]({}) <{}> {}", id, __LINE__, rc, error_msg));
        }
        session->wait_socket();
    }
}

void ohtoai::ssh::detail::ssh_channel::send_eof() {
    if (channel != nullptr) {
        libssh2_channel_send_eof(channel);
    }
}

void ohtoai::ssh::detail::ssh_channel::close() {
    if (channel != nullptr) {
        libssh2_channel_free(channel);
        channel = nullptr;
        if (session) {
            session->close_channel(id);
        }
    }
}

ohtoai::ssh::detail::ssh_session::ssh_session() {
    if (counter == 0) {
        // init sshlib
        spdlog::debug("libssh2 init");
        if (int rc = libssh2_init(0)) {
            throw std::runtime_error(fmt::format("Failed to initialize ssh library <{}>", rc));
        }
    }
    ++counter;
    session = nullptr;
}

ohtoai::ssh::detail::ssh_session::~ssh_session() {
    disconnect();
    --counter;
    if (counter == 0) {
        // deinit sshlib
        spdlog::debug("libssh2 exit");
        libssh2_exit();
    }
}

void ohtoai::ssh::detail::ssh_session::connect(const std::string &host, int port) {
    this->host = host;
    this->port = port;
    if (session != nullptr) {
        throw std::runtime_error("Session is already opened");
    }

    sock = ::socket(AF_INET, SOCK_STREAM, 0);
    if (sock == LIBSSH2_INVALID_SOCKET) {
        throw std::runtime_error("Failed to create socket");
    }
    spdlog::debug("Socket created");

    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0) {
        throw std::runtime_error("Failed to resolve host");
    }
    // log host and its ip
    spdlog::debug("Host resolved {}", host);

    struct sockaddr_in sin {};
    memcpy(&sin, res->ai_addr, sizeof sin);
    sin.sin_port = htons(port);
    freeaddrinfo(res);
    if (sin.sin_addr.s_addr == INADDR_NONE) {
        throw std::runtime_error("Failed to parse host");
    }
    spdlog::debug("Host parsed {}", inet_ntoa(sin.sin_addr));

    if (::connect(sock, reinterpret_cast<struct sockaddr*>(&sin), sizeof(sin)) != 0) {
        throw std::runtime_error("Failed to connect");
    }
    spdlog::debug("Connected to {}", host);

    session = libssh2_session_init();
    if (session == nullptr) {
        throw std::runtime_error("Failed to initialize session");
    }
    spdlog::debug("Session initialized");

    libssh2_session_set_blocking(session, 0);

    while(int rc = libssh2_session_handshake(session, sock)) {
        if (rc != LIBSSH2_ERROR_EAGAIN) {
            char *error_msg = nullptr;
            libssh2_session_last_error(session, &error_msg, nullptr, 0);
            throw std::runtime_error(fmt::format("[{}]({}) <{}> {}", get_id(), __LINE__, rc, error_msg));
        }
    }
    spdlog::info("[{}] Session connected", get_id());
}

void ohtoai::ssh::detail::ssh_session::authenticate(const std::string &username, const std::string &password) {
    this->username = username;
    if (session == nullptr) {
        throw std::runtime_error("Session is not opened");
    }
    while(int rc = libssh2_userauth_password(session, username.c_str(), password.c_str())) {
        if (rc != LIBSSH2_ERROR_EAGAIN) {
            char *error_msg = nullptr;
            libssh2_session_last_error(session, &error_msg, nullptr, 0);
            throw std::runtime_error(fmt::format("[{}]({}) <{}> {}", get_id(), __LINE__, rc, error_msg));
        }
    }
    spdlog::info("[{}] Session authenticated", get_id());
}

ohtoai::ssh::detail::ssh_channel_ptr ohtoai::ssh::detail::ssh_session::open_channel() {
    if (session == nullptr) {
        throw std::runtime_error("Session is not opened");
    }
    ssh_channel_ptr channel = std::make_shared<ssh_channel>();
    channel->session = this;
    do {
        channel->channel = libssh2_channel_open_session(session);
        if (channel->channel) {
            break;
        }
        char *error_msg = nullptr;
        auto rc = libssh2_session_last_error(session, &error_msg, nullptr, 0);
        if (rc != LIBSSH2_ERROR_EAGAIN) {
            throw std::runtime_error(fmt::format("[{}]({}) <{}> {}", channel->id, __LINE__, rc, error_msg));
        }
        wait_socket();
    } while (true);

    try {
        channel->set_env("LC_WSSH_CHANNEL_ID", channel->id);
    }
    catch (const std::exception& e) {
        spdlog::error("[{}] Try to set env, but failed.", channel->id);
        spdlog::error("{}", e.what());
    }

    spdlog::info("[{}] Channel opened", channel->id);

    channels.emplace(channel->id, channel);
    spdlog::info("[{}] Session channels opened {}", get_id(), channels.size());
    return channel;
}

void ohtoai::ssh::detail::ssh_session::close_channel(const channel_id_t &id) {
    auto iter = channels.find(id);
    if (iter != channels.end()) {
        iter->second->close();
        channels.erase(iter);
        spdlog::info("[{}] Channel closed", iter->second->id);
        spdlog::info("[{}] Session channels opened {}", get_id(), channels.size());
    }
    if (channels.empty()) {
        disconnect();
    }
}

void ohtoai::ssh::detail::ssh_session::disconnect() {
    if (session != nullptr) {
        for (auto &channel : channels) {
            channel.second->close();
        }
        libssh2_session_disconnect(session, "Bye bye");
        libssh2_session_free(session);
        session = nullptr;
        spdlog::info("[{}] Session disconnected", get_id());
    }
    if (sock != LIBSSH2_INVALID_SOCKET) {
        ::shutdown(sock, 2);
        ::close(sock);
    }
}

void ohtoai::ssh::detail::ssh_session::wait_socket() {
    struct timeval timeout;
    int rc;
    fd_set fd;
    fd_set *writefd = nullptr;
    fd_set *readfd = nullptr;
    int dir;

    timeout.tv_sec = 10;
    timeout.tv_usec = 0;

    FD_ZERO(&fd);

    FD_SET(sock, &fd);

    /* now make sure we wait in the correct direction */
    dir = libssh2_session_block_directions(session);

    if(dir & LIBSSH2_SESSION_BLOCK_INBOUND)
        readfd = &fd;

    if(dir & LIBSSH2_SESSION_BLOCK_OUTBOUND)
        writefd = &fd;

    rc = select((int)(sock + 1), readfd, writefd, nullptr, &timeout);
}

ohtoai::ssh::detail::session_id_t ohtoai::ssh::detail::ssh_session::generate_id(const std::string &host, int port, const std::string &username, const std::string &custom) {
    if (username.empty())
        return fmt::format("{}:{}{}", host, port, custom);
    else
        return fmt::format("{}@{}:{}{}", username, host, port, custom);
}

ohtoai::ssh::detail::session_id_t ohtoai::ssh::detail::ssh_session::get_id() const {
    return generate_id(host, port, username);
}

ohtoai::ssh::detail::ssh_pty_connection_manager::~ssh_pty_connection_manager() {
    spdlog::debug("ssh_pty_connection_manager destroyed");

    for (auto &session : sessions) {
        session.second->disconnect();
    }

    spdlog::debug("ssh_pty_connection_manager sessions closed");

    sessions.clear();
    channels.clear();
}

ohtoai::ssh::detail::ssh_pty_connection_manager &ohtoai::ssh::ssh_pty_connection_manager::get_instance() {
    static ssh_pty_connection_manager instance;
    return instance;
}

void ohtoai::ssh::detail::ssh_pty_connection_manager::set_max_channel_in_session(size_t max_channel_in_session) {
    this->max_channel_in_session = max_channel_in_session;
}

size_t ohtoai::ssh::detail::ssh_pty_connection_manager::get_max_channel_in_session() const {
    return max_channel_in_session;
}

size_t ohtoai::ssh::detail::ssh_pty_connection_manager::get_channel_count(detail::session_id_t session_id) const {
    std::lock_guard<std::mutex> lock(sessions_mutex);
    auto begin = sessions.lower_bound(session_id);
    auto end = sessions.upper_bound(session_id);
    size_t count = 0;
    for (auto iter = begin; iter != end; ++iter) {
        count += iter->second->channels.size();
    }
    return count;
}

size_t ohtoai::ssh::detail::ssh_pty_connection_manager::get_channel_count() const {
    return channels.size();
}

size_t ohtoai::ssh::detail::ssh_pty_connection_manager::get_channel_alive_count() const {
    return std::count_if(channels.begin(), channels.end(), [](const auto &pair) {
        return !pair.second.expired();
    });
}

size_t ohtoai::ssh::detail::ssh_pty_connection_manager::get_session_count() const {
    return sessions.size();
}

ohtoai::ssh::detail::ssh_channel_ptr ohtoai::ssh::detail::ssh_pty_connection_manager::get_channel(const std::string &host, int port, const std::string &username, const std::string &password) {
    auto session_id = detail::ssh_session::generate_id(host, port, username);

    auto session_iter = [this, &session_id]{
        std::lock_guard<std::mutex> lock(sessions_mutex);
        // find first session that has less than max_channel_in_session channels
        auto begin = sessions.lower_bound(session_id);
        auto end = sessions.upper_bound(session_id);
        return std::find_if(begin, end, [this](const auto &pair) {
            return pair.second->channels.size() < max_channel_in_session;
        });
    }();

    // if no session found, create new session
    if (session_iter == sessions.end()) {
        auto session = std::make_shared<detail::ssh_session>();
        session->connect(host, port);
        session->authenticate(username, password);
        std::lock_guard<std::mutex> lock(sessions_mutex);
        session_iter = sessions.emplace(session_id, session);
    }
    auto session = session_iter->second;
    auto channel = session->open_channel();
    channels.emplace(channel->id, channel);
    return channel;
}

ohtoai::ssh::detail::ssh_channel_ptr ohtoai::ssh::detail::ssh_pty_connection_manager::get_channel(const detail::session_id_t &id) {
    auto iter = channels.find(id);
    if (iter == channels.end()) {
        return nullptr;
    }
    return iter->second.lock();
}
