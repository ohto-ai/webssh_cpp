#include "ssh_connection.h"

#include <algorithm>
#include <cstring>
#include <memory>
#include <mutex>
#include <libssh2.h>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>
#endif
#include <stdexcept>
#include <spdlog/spdlog.h>
#include <spdlog/fmt/fmt.h>

ohtoai::ssh::detail::ssh_channel::ssh_channel():
    id(std::to_string(++id_counter)) {
    channel = nullptr;
}

ohtoai::ssh::detail::ssh_channel::~ssh_channel() {
    close();
    spdlog::debug("[{}] Channel closed", id);
}

void ohtoai::ssh::detail::ssh_channel::reserve_buffer(size_t size) {
    std::lock_guard lock(mutex_);
    buffer.reserve(size);
}

const ohtoai::mini_buffer& ohtoai::ssh::detail::ssh_channel::get_buffer() {
    std::lock_guard lock(mutex_);
    return buffer;
}

bool ohtoai::ssh::detail::ssh_channel::is_open() {
    std::lock_guard lock(mutex_);
    return channel != nullptr && libssh2_channel_eof(channel) == 0;
}

long ohtoai::ssh::detail::ssh_channel::read() {
    std::lock_guard lock(mutex_);
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

    if (rc > 0) {
        spdlog::debug("[{}] Read {} bytes", id, rc);
    }
    return rc;
}

void ohtoai::ssh::detail::ssh_channel::write(const byte* data, size_t size) {
    std::unique_lock lock(mutex_);
    if (channel == nullptr) {
        throw std::runtime_error(fmt::format("[{}] Channel is not opened", id));
    }
    auto sess = session;  // keep session alive via shared_ptr during the loop
    size_t total_written = 0;
    while (total_written < size) {
        ssize_t rc = libssh2_channel_write(channel, data + total_written, size - total_written);
        if (rc == LIBSSH2_ERROR_EAGAIN) {
            lock.unlock();
            sess->wait_socket();
            lock.lock();
            if (channel == nullptr) {
                throw std::runtime_error(fmt::format("[{}] Channel closed during write", id));
            }
            continue;
        }
        if (rc == 0) {
            throw std::runtime_error(fmt::format("[{}] Channel write returned 0 — channel may be closed", id));
        }
        if (rc < 0) {
            char *error_msg = nullptr;
            libssh2_session_last_error(sess->session, &error_msg, nullptr, 0);
            throw std::runtime_error(fmt::format("[{}]({}) <{}> {}", id, __LINE__, rc, error_msg));
        }
        total_written += static_cast<size_t>(rc);
    }
    spdlog::debug("[{}] Wrote {} bytes", id, total_written);
}

void ohtoai::ssh::detail::ssh_channel::write(const std::string &data) {
    write(reinterpret_cast<const byte*>(data.data()), data.size());
}

void ohtoai::ssh::detail::ssh_channel::set_env(const std::string &name, const std::string &value) {
    std::unique_lock lock(mutex_);
    if (channel == nullptr) {
        throw std::runtime_error(fmt::format("[{}] Channel is not opened", id));
    }
    auto sess = session;
    while (int rc = libssh2_channel_setenv(channel, name.c_str(), value.c_str())) {
        if (rc != LIBSSH2_ERROR_EAGAIN) {
            char *error_msg = nullptr;
            libssh2_session_last_error(sess->session, &error_msg, nullptr, 0);
            throw std::runtime_error(fmt::format("[{}]({}) <{}> {}", id, __LINE__, rc, error_msg));
        }
        lock.unlock();
        sess->wait_socket();
        lock.lock();
        if (channel == nullptr) {
            throw std::runtime_error(fmt::format("[{}] Channel closed during set_env", id));
        }
    }
    spdlog::debug("[{}] Env set {}={}", id, name, value);
}

void ohtoai::ssh::detail::ssh_channel::shell() {
    std::unique_lock lock(mutex_);
    if (channel == nullptr) {
        throw std::runtime_error(fmt::format("[{}] Channel is not opened", id));
    }
    auto sess = session;
    while (int rc = libssh2_channel_shell(channel)) {
        if (rc != LIBSSH2_ERROR_EAGAIN) {
            char *error_msg = nullptr;
            libssh2_session_last_error(sess->session, &error_msg, nullptr, 0);
            throw std::runtime_error(fmt::format("[{}]({}) <{}> {}", id, __LINE__, rc, error_msg));
        }
        lock.unlock();
        sess->wait_socket();
        lock.lock();
        if (channel == nullptr) {
            throw std::runtime_error(fmt::format("[{}] Channel closed during shell", id));
        }
    }
    spdlog::debug("[{}] Shell requested", id);
}

void ohtoai::ssh::detail::ssh_channel::request_pty(const std::string &pty_type) {
    std::unique_lock lock(mutex_);
    if (channel == nullptr) {
        throw std::runtime_error(fmt::format("[{}] Channel is not opened", id));
    }
    auto sess = session;
    while (int rc = libssh2_channel_request_pty(channel, pty_type.c_str())) {
        if (rc != LIBSSH2_ERROR_EAGAIN) {
            char *error_msg = nullptr;
            libssh2_session_last_error(sess->session, &error_msg, nullptr, 0);
            throw std::runtime_error(fmt::format("[{}]({}) <{}> {}", id, __LINE__, rc, error_msg));
        }
        lock.unlock();
        sess->wait_socket();
        lock.lock();
        if (channel == nullptr) {
            throw std::runtime_error(fmt::format("[{}] Channel closed during request_pty", id));
        }
    }
    spdlog::debug("[{}] Pty requested {}", id, pty_type);
}

void ohtoai::ssh::detail::ssh_channel::resize_pty(int width, int height) {
    std::unique_lock lock(mutex_);
    if (channel == nullptr) {
        throw std::runtime_error(fmt::format("[{}] Channel is not opened", id));
    }
    auto sess = session;
    spdlog::debug("[{}] Pty resized {}x{}", id, width, height);
    while (int rc = libssh2_channel_request_pty_size(channel, width, height)) {
        if (rc != LIBSSH2_ERROR_EAGAIN) {
            char *error_msg = nullptr;
            libssh2_session_last_error(sess->session, &error_msg, nullptr, 0);
            throw std::runtime_error(fmt::format("[{}]({}) <{}> {}", id, __LINE__, rc, error_msg));
        }
        lock.unlock();
        sess->wait_socket();
        lock.lock();
        if (channel == nullptr) {
            throw std::runtime_error(fmt::format("[{}] Channel closed during resize_pty", id));
        }
    }
}

void ohtoai::ssh::detail::ssh_channel::send_eof() {
    std::lock_guard lock(mutex_);
    if (channel != nullptr) {
        libssh2_channel_send_eof(channel);
    }
}

void ohtoai::ssh::detail::ssh_channel::close() {
    ssh_session_ptr sess_to_notify;
    {
        std::lock_guard lock(mutex_);
        if (channel != nullptr) {
            libssh2_channel_free(channel);
            channel = nullptr;
            sess_to_notify = std::move(session);
            // session shared_ptr is now null in this channel
        }
    }
    // Notify session outside the lock to avoid deadlock
    if (sess_to_notify) {
        sess_to_notify->close_channel(id);
    }
}

ohtoai::ssh::detail::ssh_session::ssh_session() {
#ifdef _WIN32
    static std::once_flag winsock_init_flag;
    std::call_once(winsock_init_flag, []() {
        WSADATA wsa_data;
        if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
            throw std::runtime_error("Failed to initialize WinSock");
        }
    });
#endif
    sock = LIBSSH2_INVALID_SOCKET;
    static std::once_flag libssh2_init_flag;
    std::call_once(libssh2_init_flag, []() {
        spdlog::debug("libssh2 init");
        if (int rc = libssh2_init(0)) {
            throw std::runtime_error(fmt::format("Failed to initialize ssh library <{}>", rc));
        }
    });
    ++counter;
    session = nullptr;
}

ohtoai::ssh::detail::ssh_session::~ssh_session() {
    disconnect();
    if (counter.fetch_sub(1) == 1) {
        spdlog::debug("libssh2 exit");
        libssh2_exit();
#ifdef _WIN32
        WSACleanup();
#endif
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
    auto channel = std::make_shared<ssh_channel>();
    channel->session = shared_from_this();
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
        channels.erase(iter);
        spdlog::info("[{}] Channel deregistered from session [{}], remaining {}", id, get_id(), channels.size());
    }
    if (channels.empty()) {
        disconnect();
    }
}

void ohtoai::ssh::detail::ssh_session::disconnect() {
    if (session != nullptr) {
        auto channels_to_close = std::move(channels);
        channels.clear();
        for (auto &[cid, ch] : channels_to_close) {
            ch->session.reset();  // Prevent ch->close() from calling close_channel()
            ch->close();
        }
        libssh2_session_disconnect(session, "Bye bye");
        libssh2_session_free(session);
        session = nullptr;
        spdlog::info("[{}] Session disconnected", get_id());
    }
    if (sock != LIBSSH2_INVALID_SOCKET) {
#ifdef _WIN32
        ::shutdown(sock, SD_BOTH);
        ::closesocket(sock);
#else
        ::shutdown(sock, 2);
        ::close(sock);
#endif
        sock = LIBSSH2_INVALID_SOCKET;
    }
}

void ohtoai::ssh::detail::ssh_session::wait_socket() {
    if (session == nullptr) {
        throw std::runtime_error("Session is closed");
    }
    struct timeval timeout;
    fd_set fd;
    fd_set *writefd = nullptr;
    fd_set *readfd = nullptr;
    int dir;

    timeout.tv_sec = 10;
    timeout.tv_usec = 0;

    FD_ZERO(&fd);

    FD_SET(sock, &fd);

    dir = libssh2_session_block_directions(session);

    if(dir & LIBSSH2_SESSION_BLOCK_INBOUND)
        readfd = &fd;

    if(dir & LIBSSH2_SESSION_BLOCK_OUTBOUND)
        writefd = &fd;

#ifdef _WIN32
    int rc = select(0, readfd, writefd, nullptr, &timeout);
#else
    int rc = select(sock + 1, readfd, writefd, nullptr, &timeout);
#endif
    if (rc < 0) {
#ifdef _WIN32
        throw std::runtime_error(fmt::format("select() failed: {}", WSAGetLastError()));
#else
        throw std::runtime_error(fmt::format("select() failed: {}", strerror(errno)));
#endif
    }
    // timeout (rc == 0) is acceptable; caller will retry
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
    std::shared_lock lock(sessions_mutex);
    auto begin = sessions.lower_bound(session_id);
    auto end = sessions.upper_bound(session_id);
    size_t count = 0;
    for (auto iter = begin; iter != end; ++iter) {
        count += iter->second->channels.size();
    }
    return count;
}

size_t ohtoai::ssh::detail::ssh_pty_connection_manager::get_channel_count() const {
    std::shared_lock lock(channels_mutex);
    return channels.size();
}

size_t ohtoai::ssh::detail::ssh_pty_connection_manager::get_channel_alive_count() const {
    std::shared_lock lock(channels_mutex);
    return std::count_if(channels.begin(), channels.end(), [](const auto &pair) {
        return !pair.second.expired();
    });
}

size_t ohtoai::ssh::detail::ssh_pty_connection_manager::get_session_count() const {
    std::shared_lock lock(sessions_mutex);
    return sessions.size();
}

void ohtoai::ssh::detail::ssh_pty_connection_manager::cleanup_stale_weak_ptrs() {
    std::unique_lock lock(channels_mutex);
    for (auto it = channels.begin(); it != channels.end(); ) {
        if (it->second.expired()) {
            it = channels.erase(it);
        } else {
            ++it;
        }
    }
}

ohtoai::ssh::detail::ssh_channel_ptr ohtoai::ssh::detail::ssh_pty_connection_manager::get_channel(const std::string &host, int port, const std::string &username, const std::string &password) {
    auto session_id = detail::ssh_session::generate_id(host, port, username);

    ssh_session_ptr session;
    {
        std::unique_lock lock(sessions_mutex);
        // Remove stale (disconnected) sessions for this session_id
        auto range = sessions.equal_range(session_id);
        for (auto it = range.first; it != range.second; ) {
            if (it->second->session == nullptr) {
                it = sessions.erase(it);
            } else {
                ++it;
            }
        }
        // Find the first live session with available channel capacity
        range = sessions.equal_range(session_id);
        auto it = std::find_if(range.first, range.second, [this](const auto &pair) {
            return max_channel_in_session == 0 ||
                   pair.second->channels.size() < max_channel_in_session;
        });
        if (it != range.second) {
            session = it->second;
        }
    }

    // No usable session found - create a new one
    if (!session) {
        session = std::make_shared<detail::ssh_session>();
        session->connect(host, port);
        session->authenticate(username, password);
        std::unique_lock lock(sessions_mutex);
        sessions.emplace(session_id, session);
    }

    ssh_channel_ptr channel;
    try {
        channel = session->open_channel();
    }
    catch (...) {
        // If channel creation fails, clean up the stale session if it's now empty
        std::unique_lock lock(sessions_mutex);
        if (session->channels.empty() && session->session == nullptr) {
            // Session was already disconnected; remove it
            auto range = sessions.equal_range(session_id);
            for (auto it = range.first; it != range.second; ++it) {
                if (it->second == session) {
                    sessions.erase(it);
                    break;
                }
            }
        }
        throw;
    }

    {
        std::unique_lock lock(channels_mutex);
        channels.emplace(channel->id, channel);
    }
    return channel;
}

ohtoai::ssh::detail::ssh_channel_ptr ohtoai::ssh::detail::ssh_pty_connection_manager::get_channel(const detail::session_id_t &id) {
    std::shared_lock lock(channels_mutex);
    auto iter = channels.find(id);
    if (iter == channels.end()) {
        return nullptr;
    }
    return iter->second.lock();
}

void ohtoai::ssh::detail::ssh_pty_connection_manager::close_channel(const detail::channel_id_t &id) {
    ssh_channel_ptr ch;
    {
        std::unique_lock lock(channels_mutex);
        auto iter = channels.find(id);
        if (iter == channels.end()) {
            return;
        }
        ch = iter->second.lock();
        channels.erase(iter);
    }
    if (ch) {
        ch->close();
    }
}
