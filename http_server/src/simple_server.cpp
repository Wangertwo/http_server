#include "io_context.hpp"
#include "http_server.hpp"

void server() {
    io_context ctx;
    auto server = http_server::make();
    server->get_router().route("/", [](http_server::http_request &request) {
        std::string response;
        if (request.m_body.empty()) {
            response = "你好，你的请求正文为空哦";
        } else {
            response = "你好，你的请求是: [" + request.m_body
                + "]，共 " + std::to_string(request.m_body.size())
                + " 字节";
        }
        request.write_response(200, response);
    });
    // fmt::println("正在监听：http://127.0.0.1:8080");
    server->do_start("127.0.0.1", "8080");

    ctx.join();
}

int main() {
    server();
    return 0;
}