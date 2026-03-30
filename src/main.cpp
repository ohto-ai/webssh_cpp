#include "ssh_connection/ssh_connection.h"

#include <spdlog/spdlog.h>
#include <spdlog/fmt/fmt.h>
#include <chrono>
#include <map>
#include <stdexcept>
#include <string>
#include <thread>
#include <set>
#include <mutex>
#include <vector>
#include <hv/WebSocketServer.h>
#include <hv/HttpServer.h>
#include <hv/EventLoop.h>
#include <hv/hasync.h>

class ssh_context : public std::mutex {
public:
    ohtoai::ssh::channel_id_t ssh_channel_id;
    std::set<WebSocketChannelPtr> channels_read;
    std::set<WebSocketChannelPtr> channels_write;
    void close() {
        std::lock_guard lock(*this);
        for (auto& channel : channels_read) {
            channel->close();
        }
        for (auto& channel : channels_write) {
            channel->close();
        }
        auto ssh_channel = ohtoai::ssh::ssh_pty_connection_manager::get_instance().get_channel(ssh_channel_id);
        if (ssh_channel != nullptr) {
            ssh_channel->send_eof();
            ssh_channel->close();
        }
    }
    ~ssh_context() {
        close();
    }
    inline static std::map<ohtoai::ssh::channel_id_t, std::weak_ptr<ssh_context>> ssh_contexts;
    inline static std::mutex ssh_contexts_mutex;
};

int main(int argc, char *argv[]) {
    int port = 8080;
    std::string host = "0.0.0.0";

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-d") == 0) {
            spdlog::set_level(spdlog::level::debug);
        } else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            try {
                port = std::stoi(argv[++i]);
                if (port <= 0 || port > 65535) throw std::out_of_range("port out of range");
            } catch (const std::exception& e) {
                fmt::print(stderr, "Invalid port: {}\n", argv[i]);
                return 1;
            }
        } else if (strcmp(argv[i], "-a") == 0 && i + 1 < argc) {
            host = argv[++i];
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            fmt::print("Usage: {} [-d] [-p port] [-a address]\n", argv[0]);
            fmt::print("  -d          Enable debug logging\n");
            fmt::print("  -p port     Listen port (default: 8080)\n");
            fmt::print("  -a address  Listen address (default: 0.0.0.0)\n");
            fmt::print("  -h          Show this help\n");
            return 0;
        }
    }

    // Poll interval when no SSH data is available.
    // 10ms gives good responsiveness without busy-looping.
    constexpr int kSshPollIntervalMs = 10;

    hv::WebSocketService ws;
    ws.onopen = [](const WebSocketChannelPtr& channel, const HttpRequestPtr& req) {
        spdlog::debug("{} {}", channel->peeraddr(), req->Path());
        auto channel_id = req->GetParam("id");
        if (channel_id.empty()) {
            spdlog::error("channel_id is empty");
            channel->close();
            return;
        }

        // Find or create ssh_context for this channel_id
        {
            std::lock_guard<std::mutex> guard(ssh_context::ssh_contexts_mutex);
            auto it = ssh_context::ssh_contexts.find(channel_id);
            if (it != ssh_context::ssh_contexts.end()) {
                auto ctx = it->second.lock();
                if (ctx != nullptr) {
                    // Attach as read-only observer to an existing session
                    std::lock_guard lock(*ctx);
                    ctx->channels_read.emplace(channel);
                    spdlog::info("[{}] Attached read-only WebSocket to existing ssh_context", channel_id);
                    return;
                }
            }
        }

        auto ctx = channel->newContextPtr<ssh_context>();
        {
            std::lock_guard<std::mutex> guard(ssh_context::ssh_contexts_mutex);
            ssh_context::ssh_contexts.emplace(channel_id, ctx);
        }
        ctx->ssh_channel_id = channel_id;
        ctx->channels_read.emplace(channel);
        ctx->channels_write.emplace(channel);

        auto ssh_channel = ohtoai::ssh::ssh_pty_connection_manager::get_instance().get_channel(ctx->ssh_channel_id);
        if (ssh_channel == nullptr) {
            spdlog::error("[{}] ssh_channel is null", channel_id);
            channel->close();
            return;
        }

        hv::async([ctx] {
            while (true) {
                auto ssh_channel = ohtoai::ssh::ssh_pty_connection_manager::get_instance().get_channel(ctx->ssh_channel_id);
                if (ssh_channel == nullptr) {
                    spdlog::error("[{}] ssh_channel is null", ctx->ssh_channel_id);
                    break;
                }

                {
                    std::lock_guard lock(*ctx);
                    if (ctx->channels_write.empty()) {
                        spdlog::info("[{}] All write channels gone, stopping read loop", ctx->ssh_channel_id);
                        break;
                    }
                }

                long rc = 0;
                try {
                    rc = ssh_channel->read();
                }
                catch (const std::exception& e) {
                    spdlog::error("[{}] SSH read failed: {}", ctx->ssh_channel_id, e.what());
                    break;
                }

                if (rc == 0) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(kSshPollIntervalMs));
                    continue;
                }

                std::lock_guard lock(*ctx);
                std::vector<WebSocketChannelPtr> to_remove;
                for (auto& ws_channel : ctx->channels_read) {
                    if (!ws_channel->isConnected()) {
                        to_remove.push_back(ws_channel);
                        continue;
                    }
                    ws_channel->send(ssh_channel->get_buffer().data, ssh_channel->get_buffer().size);
                }
                for (auto& ws_channel : to_remove) {
                    ctx->channels_read.erase(ws_channel);
                    ctx->channels_write.erase(ws_channel);
                }
            }
            ctx->close();
        });
    };
    ws.onmessage = [](const WebSocketChannelPtr& channel, const std::string& msg) {
        spdlog::debug("{} {}", channel->peeraddr(), msg);
        auto ctx = channel->getContextPtr<ssh_context>();
        if (ctx == nullptr) {
            spdlog::error("ctx is null");
            return;
        }

        // Read-only channels must not send data
        {
            std::lock_guard lock(*ctx);
            if (ctx->channels_write.find(channel) == ctx->channels_write.end()) {
                spdlog::debug("[{}] Ignoring message from read-only channel", ctx->ssh_channel_id);
                return;
            }
        }

        auto ssh_channel = ohtoai::ssh::ssh_pty_connection_manager::get_instance().get_channel(ctx->ssh_channel_id);
        if (ssh_channel == nullptr) {
            spdlog::error("ssh_channel is null");
            ctx->close();
            return;
        }

        try {
            hv::Json j = hv::Json::parse(msg);
            if (j.contains("resize")) {
                int width = j["resize"][0];
                int height = j["resize"][1];
                ssh_channel->resize_pty(width, height);
            } else if (j.contains("data")) {
                auto data = j["data"].get<std::string>();
                ssh_channel->write(data);
            }
        }
        catch (const std::exception& e) {
            spdlog::error("[{}] Failed to handle message: {}", ctx->ssh_channel_id, e.what());
        }
    };
    ws.onclose = [](const WebSocketChannelPtr& channel) {
        spdlog::debug("{}", channel->peeraddr());
        auto ctx = channel->getContextPtr<ssh_context>();
        if (ctx == nullptr) {
            return;
        }
        {
            std::lock_guard lock(*ctx);
            ctx->channels_read.erase(channel);
            ctx->channels_write.erase(channel);
            if (!ctx->channels_write.empty()) {
                // Other write-capable connections remain; keep SSH alive
                channel->deleteContextPtr();
                return;
            }
        }
        ctx->close();
        channel->deleteContextPtr();
    };

    HttpService http;
    http.Static("/", "static");
    http.POST("/", [](const HttpContextPtr& ctx) {
        spdlog::info("{}:{} {}", ctx->ip(), ctx->port(), ctx->path());
        auto hostname = ctx->get("hostname");
        auto port = ctx->get("port", 22);
        auto username = ctx->get("username");
        auto password = ctx->get("password");
        auto term = ctx->get("term");
        auto channel_id = ctx->get("channel");

        spdlog::debug("Receive login request: hostname={}, port={}, username={}, term={}, channel_id={}",
                      hostname, port, username, term, channel_id);

        ohtoai::ssh::ssh_channel_ptr ssh_channel {};
        if (!channel_id.empty()) {
            ssh_channel = ohtoai::ssh::ssh_pty_connection_manager::get_instance().get_channel(channel_id);
            if (ssh_channel == nullptr) {
                ctx->setStatus(HTTP_STATUS_NOT_FOUND);
                return ctx->send("channel not found");
            }
        }
        else {
            if (hostname.empty() || username.empty()) {
                ctx->setStatus(HTTP_STATUS_BAD_REQUEST);
                return ctx->send("hostname and username are required");
            }
            try {
                ssh_channel = ohtoai::ssh::ssh_pty_connection_manager::get_instance().get_channel(hostname, port, username, password);
                if (ssh_channel == nullptr) {
                    ctx->setStatus(HTTP_STATUS_INTERNAL_SERVER_ERROR);
                    return ctx->send("failed to create ssh channel");
                }
                ssh_channel->set_env("LC_WSSH_WEBSOCKET_HOST", ctx->host());
                ssh_channel->set_env("LC_WSSH_WEBSOCKET_URL", ctx->url());
                ssh_channel->set_env("LC_WSSH_WEBSOCKET_CLIENT_IP", ctx->header("X-Real-IP", ctx->ip()));
                ssh_channel->request_pty(term.empty() ? "xterm-256color" : term);
                ssh_channel->shell();
            }
            catch (const std::exception& e) {
                spdlog::error("SSH connection failed: {}", e.what());
                ctx->setStatus(HTTP_STATUS_FORBIDDEN);
                return ctx->send(e.what());
            }
        }

        hv::Json resp;
        resp["id"] = ssh_channel->id;
        resp["encoding"] = "utf-8";
        return ctx->send(resp.dump(2));
    });

    hv::WebSocketServer server;
    server.port = port;
    server.host = host.c_str();

    server.registerHttpService(&http);
    server.registerWebSocketService(&ws);

    spdlog::info("WebSSH server starting on {}:{}", host, port);
    server.run();
    return 0;
}
