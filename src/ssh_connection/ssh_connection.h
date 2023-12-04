#pragma once

#include <vector>
#include <string>
#include <memory>
#include <map>
#include <atomic>

typedef struct _LIBSSH2_SESSION                     LIBSSH2_SESSION;
typedef struct _LIBSSH2_CHANNEL                     LIBSSH2_CHANNEL;
namespace ohtoai::ssh
{
    namespace detail
    {
        using byte = char;
        using bytes = std::vector<byte>;
        using channel_id_t = std::string;

        class ssh_channel;
        class ssh_session;
        using ssh_channel_ptr = std::shared_ptr<ssh_channel>;
        using ssh_session_ptr = std::shared_ptr<ssh_session>;

        class ssh_channel {
            friend class ssh_session;
        public:
            ssh_channel();
            ~ssh_channel();

            void reserve_buffer(size_t size);
            bytes& get_buffer();
            bool is_open();
            long read();
            void write(const bytes& data);
            void write(const byte* data, size_t size);
            void write(const std::string &data);
            void shell();
            void request_pty(const std::string &pty_type = "vanilla");
            void resize_pty(int width, int height);
            void disconnect();
            void close();
            const channel_id_t id;
        protected:
            LIBSSH2_CHANNEL *channel;
            ssh_session *session;
            bytes buffer;
        };


        class ssh_session {
            friend class ssh_channel;
        public:
            ssh_session();
            ~ssh_session();

            void connect(const std::string &host, int port);
            void authenticate(const std::string &username, const std::string &password);
            ssh_channel_ptr open_channel();
            void disconnect();
            void close_channel(const channel_id_t &id);
            void wait_socket();
        protected:
            LIBSSH2_SESSION *session;
            std::map<channel_id_t, ssh_channel_ptr> channels;
            int sock;
            inline static std::atomic_size_t counter = 0;
        };
    }

    using detail::ssh_channel;
    using detail::ssh_session;
    using detail::ssh_channel_ptr;
    using detail::ssh_session_ptr;
    using detail::channel_id_t;
}
