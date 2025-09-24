#include <bytes_buffer.hpp>
#include <error_handle.hpp>
#include <expected.hpp>
#include <io_context.hpp>
#include <timer_context.hpp>
#include <callback.hpp>
#include <http_codec.hpp>

struct http_server : std::enable_shared_from_this<http_server>
{
    address_resolver::address m_addr;
    async_file m_listen;

    using pointer = std::shared_ptr<http_server>;
    static pointer make() 
    {
        return std::make_shared<http_server>();
    }

    struct http_request 
    {
        std::string m_method;
        std::string m_url;
        std::string m_body;
        
        response_writer<>* m_res_writer = nullptr;
        callback<> m_resume;
        
        void write_response(int status, std::string_view content, 
            std::string_view content_type = "text/plain;charset=utf-8") 
        {
            m_res_writer->begin_header(status);
            m_res_writer->write_header("Server", "co_http");
            m_res_writer->write_header("Connection", "keep-alive");
            m_res_writer->write_header("Content-Type", content_type);
            m_res_writer->write_header("Content-Length", std::to_string(content.size()));
            m_res_writer->end_header();
            m_res_writer->write_body(content);
            
            m_resume(); /* do_write */ 
        }
    };

    struct http_router
    {
        std::map<std::string, callback<http_request&>> m_routes;

        void route(std::string url, callback<http_request&> cb) 
        {
            m_routes.insert_or_assign(url, std::move(cb));
        }

        void handle(http_request& request) 
        {
            auto it = m_routes.find(request.m_url);
            if(it != m_routes.end()) 
            {
                return it->second(multishot_call, request);
            }
            return request.write_response(404, "404 Not Found");
        }
    };

    http_router m_router;

    /* 外部初始化router */
    http_router& get_router() 
    {
        return m_router;
    } 

    struct http_connection_handler : std::enable_shared_from_this<http_connection_handler>
    {
        async_file m_conn;
        bytes_buffer m_buf{1024};
        request_parser<> m_req_parser;
        response_writer<> m_res_writer;
        http_request m_request;
        http_router* m_router;

        using pointer = std::shared_ptr<http_connection_handler>;
        static pointer make() 
        {
            return std::make_shared<pointer::element_type>();
        }

        void do_start(http_router* router, int connid)  
        {
            m_router = router;
            m_conn = async_file{connid};
            do_read();
        }

        void do_read() 
        {
            /* 启动定时器 */
            using namespace std::chrono_literals;
            stop_source stop_io(std::in_place); 
            stop_source stop_timer(std::in_place);

            io_context::get().set_timeout(10s, [stop_io] {
                stop_io.request_stop(); /* 定时器触发，停止读取 */ 
                std::cout << "定时器触发，停止读取" << std::endl;
            }, stop_timer);

            return m_conn.async_read(m_buf, [self = shared_from_this(), stop_timer] (expected<size_t> read_bytes) 
            {
                stop_timer.request_stop(); /* 读取触发，停止定时器 */ 

                if(read_bytes.error()) 
                    return;

                auto n = read_bytes.value();
                if(n == 0) 
                    /* 如果读到 EOF，说明对面，关闭了连接 */
                    return;

                /* 解析请求数据 */
                self->m_req_parser.push_chunk(self->m_buf.subspan(0, n));

                if(!self->m_req_parser.request_finished()) 
                    self->do_read(); /* 继续读 */
                else 
                    self->do_handle(); /* 继续写 */
            }, stop_io);
        }

        void do_handle()
        {
            m_request.m_url = m_req_parser.url();
            m_request.m_method = m_req_parser.method();
            m_request.m_body = std::move(m_req_parser.body());
            m_request.m_res_writer = &m_res_writer;
            m_request.m_resume = [self = shared_from_this()]
            {
                self->do_write(self->m_res_writer.buffer());
            };
            m_req_parser.reset_state();
            m_router->handle(m_request);
        }

        void do_write(bytes_const_view buf) 
        {
            m_conn.async_write(buf, [buf, self = shared_from_this()](expected<size_t> write_bytes) 
            {
                if(write_bytes.error()) 
                    return;

                auto n = write_bytes.value();
                if(buf.size() == n) 
                {
                    self->m_res_writer.reset_state();
                    return self->do_read();
                }

                return self->do_write(buf.subspan(n));
            });
        }
    };

    void do_start(std::string ip, std::string port) 
    {
        address_resolver resolver;
        auto server_info = resolver.resolve(ip, port);
        std::cout << "正在监听：" << ip << " " << port << std::endl;
        m_listen = async_file::async_bind(server_info);
        return do_accept();
    }

    void do_accept() 
    {
        return m_listen.async_accept(m_addr, [self = shared_from_this()](expected<int> connid) 
        {
            auto connfd = connid.expect("accept");
            http_connection_handler::make()->do_start(&self->m_router, connfd);
            return self->do_accept();
        });
    }
};
