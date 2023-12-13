#include "ssh_connection/ssh_connection.h"

#include <spdlog/spdlog.h>
#include <chrono>
#include <thread>
#include <set>
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
};

int main(int argc, char *argv[]) {
    if (argc > 1 && strcmp(argv[1], "-d") == 0 ) {
        spdlog::set_level(spdlog::level::debug);
    }

    hv::WebSocketService ws;
    ws.onopen = [](const WebSocketChannelPtr& channel, const HttpRequestPtr& req) {
        spdlog::debug("{} {}", channel->peeraddr(), req->Path());
        auto channel_id = req->GetParam("id");
        if (channel_id.empty()) {
            spdlog::error("channel_id is empty");
            return;
        }

        // find ssh_context by channel_id
        auto it = ssh_context::ssh_contexts.find(channel_id);
        if (it != ssh_context::ssh_contexts.end()) {
            auto ctx = it->second.lock();
            if (ctx != nullptr) {
                ctx->channels_read.emplace(channel);
                spdlog::info("[{}] Add channel to existing ssh_context", channel_id);
                return;
            }
        }

        auto ctx = channel->newContextPtr<ssh_context>();
        ssh_context::ssh_contexts.emplace(channel_id, ctx);
        ctx->ssh_channel_id = channel_id;
        ctx->channels_read.emplace(channel);
        ctx->channels_write.emplace(channel);
        auto ssh_channel = ohtoai::ssh::ssh_pty_connection_manager::get_instance().get_channel(ctx->ssh_channel_id);
        if (ssh_channel == nullptr) {
            spdlog::error("[{}] ssh_channel is null", channel_id);
            return;
        }

        hv::async([ctx] {
            while (true) {
                auto ssh_channel = ohtoai::ssh::ssh_pty_connection_manager::get_instance().get_channel(ctx->ssh_channel_id);
                if (ssh_channel == nullptr) {
                    spdlog::error("[{}] ssh_channel is null", ctx->ssh_channel_id);
                    break;
                }
                if (ctx->channels_write.empty()) {
                    spdlog::error("[{}] channels_write is empty", ctx->ssh_channel_id);
                    break;
                }
                if (ssh_channel->read() <= 0) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                    continue;
                }

                std::lock_guard lock(*ctx);
                for (auto& channel : ctx->channels_read) {
                    if (!channel->isConnected()) {
                        ctx->channels_read.erase(channel);
                        ctx->channels_write.erase(channel);
                        continue;
                    }
                    channel->send(ssh_channel->get_buffer().data, ssh_channel->get_buffer().size);
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
        auto ssh_channel = ohtoai::ssh::ssh_pty_connection_manager::get_instance().get_channel(ctx->ssh_channel_id);
        if (ssh_channel == nullptr) {
            spdlog::error("ssh_channel is null");
            ctx->close();
            return;
        }

        hv::Json j = hv::Json::parse(msg);
        if (j.contains("resize")) {
            int width = j["resize"][0];
            int height = j["resize"][1];
            ssh_channel->resize_pty(width, height);
        } else if (j.contains("data")) {
            auto data = j["data"].get<std::string>();
            try {
                ssh_channel->write(data);
            }
            catch (const std::exception& e) {
                spdlog::error("[{}] Try to write {} bytes, but failed.", ssh_channel->id, data.size());
                spdlog::error("{}", e.what());
            }
        }
    };
    ws.onclose = [](const WebSocketChannelPtr& channel) {
        spdlog::debug("{}", channel->peeraddr());
        auto ctx = channel->getContextPtr<ssh_context>();
        if (ctx == nullptr) {
            spdlog::error("ctx is null");
            return;
        }
        auto ssh_channel = ohtoai::ssh::ssh_pty_connection_manager::get_instance().get_channel(ctx->ssh_channel_id);
        if (ssh_channel == nullptr) {
            spdlog::error("ssh_channel is null");
            ctx->close();
            return;
        }
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

        spdlog::debug("Receive login request: hostname={}, port={}, username={}, password={}, term={}, channel_id={}",
                      hostname, port, username, password, term, channel_id);

        ohtoai::ssh::ssh_channel_ptr ssh_channel {};
        if (!channel_id.empty()) {
            ssh_channel = ohtoai::ssh::ssh_pty_connection_manager::get_instance().get_channel(channel_id);
            if (ssh_channel == nullptr) {
                ctx->setStatus(HTTP_STATUS_FORBIDDEN);
                return ctx->send("ssh_channel is null");
            }
            // todo: Need attach to original ssh_channel
        }
        else {
            if (hostname.empty() || username.empty() || password.empty()) {
                ctx->setStatus(HTTP_STATUS_FORBIDDEN);
                return ctx->send("hostname, username, password are required");
            }
            ssh_channel = ohtoai::ssh::ssh_pty_connection_manager::get_instance().get_channel(hostname, port, username, password);
            if (ssh_channel == nullptr) {
                ctx->setStatus(HTTP_STATUS_FORBIDDEN);
                return ctx->send("ssh_channel is null");
            }
            ssh_channel->set_env("LC_WSSH_WEBSOCKET_HOST", ctx->host());
            ssh_channel->set_env("LC_WSSH_WEBSOCKET_URL", ctx->url());
            ssh_channel->set_env("LC_WSSH_WEBSOCKET_CLIENT_IP", ctx->header("X-Real-IP", ctx->ip()));
            ssh_channel->request_pty(term);
            ssh_channel->shell();
        }

        hv::Json resp;
        resp["id"] = ssh_channel->id;
        resp["encoding"] = "utf-8";
        return ctx->send(resp.dump(2));
    });

    hv::WebSocketServer server;
    server.port = 8080;

    server.registerHttpService(&http);
    server.registerWebSocketService(&ws);
    server.run();
    return 0;
}
