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
    ohtoai::ssh::channel_id_t ssh_channel_id;
    auto get_channel() {
        return channels.at(ssh_channel_id);
    }
    bool exists() {
        return exists_channel(ssh_channel_id);
    }
    
    inline static bool exists_channel(ohtoai::ssh::channel_id_t ssh_channel_id) {
        return channels.find(ssh_channel_id) != channels.end();
    }
    inline static bool exists_session(ohtoai::ssh::session_id_t ssh_session_id) {
        return sessions.find(ssh_session_id) != sessions.end();
    }

    inline static std::map<ohtoai::ssh::session_id_t, ohtoai::ssh::ssh_session_ptr> sessions;
    inline static std::map<ohtoai::ssh::session_id_t, ohtoai::ssh::ssh_channel_ptr> channels;
};

int main(int argc, char *argv[]) {
    // spdlog::set_level(spdlog::level::debug);

    hv::WebSocketService ws;
    ws.onopen = [](const WebSocketChannelPtr& channel, const HttpRequestPtr& req) {
        spdlog::debug("{} {}", channel->peeraddr(), req->Path());
        auto channel_id = req->GetParam("id");
        auto ctx = channel->newContextPtr<ssh_context>();
        ctx->ssh_channel_id = channel_id;
        auto ssh_channel = ctx->get_channel();
        if (ssh_channel == nullptr) {
            spdlog::error("[{}] ssh_channel is null", channel_id);
            return;
        }

        hv::async([ssh_channel, channel]() {
            while (ssh_channel->is_open() && channel->isConnected()) {
                if (ssh_channel->read() <= 0) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                    continue;
                }
                channel->send(ssh_channel->get_buffer().data, ssh_channel->get_buffer().size);
            }
            ssh_channel->disconnect();
            channel->close();
        });
    };
    ws.onmessage = [](const WebSocketChannelPtr& channel, const std::string& msg) {
        spdlog::debug("{} {}", channel->peeraddr(), msg);
        auto ctx = channel->getContextPtr<ssh_context>();
        if (ctx == nullptr) {
            spdlog::error("ctx is null");
            return;
        }
        auto ssh_channel = ctx->get_channel();
        if (ssh_channel == nullptr) {
            spdlog::error("ssh_channel is null");
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
        auto ssh_channel = ctx->get_channel();
        if (ssh_channel == nullptr) {
            spdlog::error("ssh_channel is null");
            return;
        }
        channel->deleteContextPtr();
        ssh_context::channels.erase(ssh_channel->id);
        ssh_channel->disconnect();
        ssh_channel->close();
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

        auto session_key = ohtoai::ssh::ssh_session::generate_id(hostname, port, username, fmt::format("{}_{}", ctx->ip(), ctx->port()));

        if (!ssh_context::exists_session(session_key)) {
            ohtoai::ssh::ssh_session_ptr session{};
            try {
                session = std::make_shared<ohtoai::ssh::ssh_session>();
                session->connect(hostname, port);
                session->authenticate(username, password);
            }
            catch (const std::exception& e) {
                spdlog::error("{}", e.what());
                ctx->setStatus(HTTP_STATUS_FORBIDDEN);
                return ctx->send(e.what());
            }
            if (session) {
                ssh_context::sessions[session_key] = session;
            }
            else {
                ctx->setStatus(HTTP_STATUS_FORBIDDEN);
                spdlog::error("Cannot connect to server");
                return ctx->send("Cannot connect to server");
            }
        }
        auto session = ssh_context::sessions[session_key];
        auto ssh_channel = session->open_channel();
        ssh_channel->set_env("LC_WSSH_WEBSOCKET_HOST", ctx->host());
        ssh_channel->set_env("LC_WSSH_WEBSOCKET_URL", ctx->url());
        ssh_channel->set_env("LC_WSSH_WEBSOCKET_CLIENT_IP", ctx->header("X-Real-IP", ctx->ip()));
        ssh_channel->request_pty(term);
        ssh_channel->shell();
        ssh_context::channels[ssh_channel->id] = ssh_channel;

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
