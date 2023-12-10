#pragma once

#include "mini_buffer.hpp"
#include <vector>
#include <string>
#include <memory>
#include <map>
#include <atomic>
#include <mutex>

typedef struct _LIBSSH2_SESSION                     LIBSSH2_SESSION;
typedef struct _LIBSSH2_CHANNEL                     LIBSSH2_CHANNEL;
namespace ohtoai::ssh
{
    namespace detail
    {
        using byte = char;
        using channel_id_t = std::string;
        using session_id_t = std::string;
        class mini_buffer;

        class ssh_channel;
        class ssh_session;
        using ssh_channel_ptr = std::shared_ptr<ssh_channel>;
        using ssh_channel_weak_ptr = std::weak_ptr<ssh_channel>;
        using ssh_session_ptr = std::shared_ptr<ssh_session>;

        class ssh_channel {
            friend class ssh_session;
            friend class ssh_pty_connection_manager;
        public:
            ssh_channel();
            ~ssh_channel();

            void reserve_buffer(size_t size);
            const ohtoai::mini_buffer& get_buffer();
            bool is_open();
            long read();
            void write(const byte* data, size_t size);
            void write(const std::string &data);
            void shell();
            void set_env(const std::string &name, const std::string &value);
            void request_pty(const std::string &pty_type = "vanilla");
            void resize_pty(int width, int height);
            void send_eof();
            void close();
            const channel_id_t id;
        protected:
            LIBSSH2_CHANNEL *channel = nullptr;
            ssh_session *session = nullptr;
            ohtoai::mini_buffer buffer {4096};
        };


        class ssh_session {
            friend class ssh_channel;
            friend class ssh_pty_connection_manager;
        public:
            ssh_session();
            ~ssh_session();

            static session_id_t generate_id(const std::string &host, int port, const std::string &username, const std::string &custom = "");
            session_id_t get_id() const;
            void connect(const std::string &host, int port);
            void authenticate(const std::string &username, const std::string &password);
            ssh_channel_ptr open_channel();
            void disconnect();
            void close_channel(const channel_id_t &id);
            void wait_socket();
        protected:
            std::string host;
            int port;
            std::string username;
            LIBSSH2_SESSION *session = nullptr;
            std::map<channel_id_t, ssh_channel_ptr> channels;
            int sock;
            inline static std::atomic_size_t counter = 0;
        };

        class ssh_pty_connection_manager {
        public:

            static ssh_pty_connection_manager& get_instance();

            void set_max_channel_in_session(size_t max_channel_in_session); // 0 means no limit, default is 3
            size_t get_max_channel_in_session() const;

            size_t get_channel_count(detail::session_id_t) const;
            size_t get_channel_count() const;
            size_t get_channel_alive_count() const;
            size_t get_session_count() const;

            detail::ssh_channel_ptr get_channel(const std::string &host, int port, const std::string &username, const std::string &password);
            detail::ssh_channel_ptr get_channel(const detail::session_id_t &id);
            void close_channel(const detail::channel_id_t &id);
        protected:
            std::multimap<detail::session_id_t, detail::ssh_session_ptr> sessions;
            std::map<detail::channel_id_t, detail::ssh_channel_weak_ptr> channels;
            size_t max_channel_in_session = 3;

            mutable std::mutex sessions_mutex;
        protected:
            ssh_pty_connection_manager() = default;
            ssh_pty_connection_manager(const ssh_pty_connection_manager&) = delete;
            ssh_pty_connection_manager(ssh_pty_connection_manager&&) = delete;
            ssh_pty_connection_manager& operator=(const ssh_pty_connection_manager&) = delete;
            ssh_pty_connection_manager& operator=(ssh_pty_connection_manager&&) = delete;
            virtual ~ssh_pty_connection_manager();
        };
    }

    using detail::ssh_channel;
    using detail::ssh_session;
    using detail::ssh_channel_ptr;
    using detail::ssh_session_ptr;
    using detail::channel_id_t;
    using detail::session_id_t;
    using detail::ssh_pty_connection_manager;
}
