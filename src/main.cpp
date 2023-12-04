#include "ssh_connection/ssh_connection.h"

#include <spdlog/spdlog.h>
#include <chrono>
#include <thread>
#include <hv/WebSocketServer.h>
#include <hv/HttpServer.h>
#include <hv/EventLoop.h>
#include <hv/hasync.h>

class ssh_context {
public:
    ohtoai::ssh::ssh_channel_ptr ssh_channel;
};

int main(int argc, char *argv[]) {
    spdlog::set_level(spdlog::level::debug);

    std::map<std::string, ohtoai::ssh::ssh_session_ptr> sessions;
    std::map<std::string, ohtoai::ssh::ssh_channel_ptr> channels;

    hv::WebSocketService ws;
    ws.onopen = [&sessions, &channels](const WebSocketChannelPtr& channel, const HttpRequestPtr& req) {
        spdlog::info("{} {}", channel->peeraddr(), req->Path());
        auto channel_id = req->GetParam("id");
        auto ssh_channel = channels[channel_id];
        if (ssh_channel == nullptr) {
            spdlog::error("[{}] ssh_channel is null", channel_id);
            return;
        }
        auto ctx = channel->newContext<ssh_context>();
        ctx->ssh_channel = ssh_channel;

        hv::async([ssh_channel, channel]() {
            while (true) {
                auto len = ssh_channel->read();
                if (len <= 0) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                    continue;
                }
                channel->send(ssh_channel->get_buffer().data(), len);
            }
        });
    };
    ws.onmessage = [](const WebSocketChannelPtr& channel, const std::string& msg) {
        spdlog::info("{} {}", channel->peeraddr(), msg);
        auto ctx = channel->getContextPtr<ssh_context>();
        if (ctx == nullptr) {
            spdlog::error("ctx is null");
            return;
        }
        if (ctx->ssh_channel == nullptr) {
            spdlog::error("ssh_channel is null");
            return;
        }

        hv::Json j = hv::Json::parse(msg);
        if (j.contains("resize")) {
            int width = j["resize"][0];
            int height = j["resize"][1];
            ctx->ssh_channel->resize_pty(width, height);
        } else if (j.contains("data")) {
            ctx->ssh_channel->write(j["data"].get<std::string>());
        }
    };
    ws.onclose = [&channels](const WebSocketChannelPtr& channel) {
        spdlog::info("{}", channel->peeraddr());
        auto ctx = channel->getContextPtr<ssh_context>();
        if (ctx == nullptr) {
            spdlog::error("ctx is null");
            return;
        }
        if (ctx->ssh_channel == nullptr) {
            spdlog::error("ssh_channel is null");
            return;
        }
        ctx->ssh_channel->disconnect();
        channels.erase(ctx->ssh_channel->id);
    };

    HttpService http;
    http.Static("/", "static");
    http.POST("/", [&sessions, &channels](const HttpContextPtr& ctx) {
        spdlog::info("{}:{} {}", ctx->ip(), ctx->port(), ctx->path());
        auto hostname = ctx->get("hostname");
        auto port = ctx->get("port", 22);
        auto username = ctx->get("username");
        auto password = ctx->get("password");
        auto term = ctx->get("term");

        auto session_key = fmt::format("{}@{}:{}", username, hostname, port);

        if (sessions.find(session_key) == sessions.end()) {
            auto session = std::make_shared<ohtoai::ssh::ssh_session>();
            try {
                sessions[session_key]->connect(hostname, port);
                sessions[session_key]->authenticate(username, password);
            }
            catch (const std::exception& e) {
                spdlog::error("{}", e.what());
                return ctx->send(e.what(), 500);
            }
            sessions[session_key] = session;
        }
        auto session = sessions[session_key];
        auto ssh_channel = session->open_channel();
        ssh_channel->request_pty(term);
        ssh_channel->shell();
        channels[ssh_channel->id] = ssh_channel;

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
