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

        struct ssh_buffer {
            char *data;
            size_t size;
            size_t capacity;

            ssh_buffer();
            ssh_buffer(size_t capacity);

            ~ssh_buffer();

            operator char*();
            operator const char*() const;

            void reserve(size_t capacity);

            void resize(size_t size);

            void clear();

            void append(const char *data, size_t size);

            void append(const std::string &data);

            void append(const ssh_buffer &buffer);
        };

        using byte = char;
        using channel_id_t = std::string;
        using session_id_t = std::string;

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
            const ssh_buffer& get_buffer();
            bool is_open();
            long read();
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
            ssh_buffer buffer {4096};
        };


        class ssh_session {
            friend class ssh_channel;
        public:
            ssh_session();
            ~ssh_session();

            static session_id_t generate_id(const std::string &host, int port, const std::string &username);
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
    using detail::session_id_t;
}
