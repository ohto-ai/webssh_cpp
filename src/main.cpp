#include "ssh_connection/ssh_connection.h"

#include <spdlog/spdlog.h>
#include <chrono>
#include <thread>

int main(int argc, char *argv[]) {
    spdlog::set_level(spdlog::level::debug);
    if (argc < 4) {
        fmt::print("Usage: {} <hostname> <username> <password> [command]\n", argv[0]);
        return 1;
    }
    ohtoai::ssh::ssh_session session;
    auto hostname = argv[1];
    auto username = argv[2];
    auto password = argv[3];
    session.connect(hostname, 22);
    session.authenticate(username, password);
    auto channel = session.open_channel();

    channel->request_pty("xterm-256color");
    channel->shell();

    for (int idx = 4; idx < argc; ++idx) {
        channel->write(argv[idx]);
        channel->write("\n");
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(1000));

    while (channel->is_open()) {
        auto sz = channel->read();
        if (sz <= 0) {
            channel->disconnect();
            break;
        }
        fmt::print("{}", channel->get_buffer().data());
    }

    session.close_channel(channel->id);
    session.disconnect();

    return 0;
}
