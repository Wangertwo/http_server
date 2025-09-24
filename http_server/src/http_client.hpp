#pragma once

#include <map>
#include <memory>
#include <string>
#include "expected.hpp"
#include "stop_source.hpp"
#include "http_codec.hpp"
#include "bytes_buffer.hpp"

struct http_client : std::enable_shared_from_this<http_client>
{
    using string_map = std::map<std::string, std::string>;
    using pointer = std::shared_ptr<http_client>;

    static pointer make() 
    {
        return std::make_shared<pointer::element_type>();
    }

    struct http_request
    {
        std::string method;
        std::string url;
        std::string body;
        string_map headers{};
    };

    struct http_response 
    {
        int status;
        std::string body;
        string_map headers{};
    };

    struct _http_url_parser 
    {
        std::string m_hostname{};
        std::string m_scheme{};
        std::string m_url{};

        _http_url_parser() = default;

        /* scheme://hostname/url */
        _http_url_parser(std::string url) : m_url(std::move(url)) 
        {
            auto pos = m_url.find("://");
            if(pos == std::string::npos) 
            {
                m_scheme = "http";
                pos = 0;
            } else {
                m_scheme = m_url.substr(0, pos);
                m_url = m_url.substr(pos + 3);
            }

            pos = m_url.find("/");
            if(pos == std::string::npos) 
            {
                m_hostname = m_url;
                m_url = "/";
            } else {
                m_hostname = m_url.substr(0, pos);
                m_url = m_url.substr(pos);
            } 
        }
    };

    struct http_connection_handler : std::enable_shared_from_this<http_connection_handler>
    {
        using pointer = std::shared_ptr<http_connection_handler>;

        static pointer make() 
        {
            return std::make_shared<pointer::element_type>();
        }

        request_writer<> m_request_writer;
        response_parser<> m_response_parser;
        bytes_buffer m_buf{1024};
        http_request m_request;
        _http_url_parser m_parsed_url;
        callback<expected<int>, http_response const&> m_cb;
        stop_source m_stop;
        async_file m_conn;
        
        address_resolver::address_info _resolve_address(address_resolver &res) {
            std::string service = m_parsed_url.m_scheme;
            std::string name = m_parsed_url.m_hostname;
            auto colon = name.rfind(':');
            if (colon != std::string::npos) {
                service = name.substr(colon + 1);
                name = name.substr(0, colon);
            }
            return res.resolve(name, service);
        }

        void do_request(http_request request,
                        _http_url_parser const& parsed_url,
                        callback<expected<int>, http_response const&> cb,
                        stop_source stop = {}) 
        {
            m_request =  std::move(request);
            m_cb = std::move(cb);
            m_stop = stop;
            if(m_conn) /* 复用现有连接 */
            {
                return do_compose();
            }
            m_parsed_url = std::move(parsed_url);
            // "http://142857.red/" 变成
            // m_hostname = "142857.red";
            // m_scheme = "http";
            // m_request.url = "/";
            address_resolver res;
            auto addr = _resolve_address(res);
            m_conn = async_file{addr.create_socket()};
            return m_conn.async_connect(addr, [self = shared_from_this()](expected<int> ret) mutable 
            {
                ret.expect("connect");
                self->do_compose();
            }, m_stop);
        }

        void do_compose() 
        {
            m_request_writer.begin_header(m_request.method, m_request.url);
            m_request_writer.write_header("Host", m_parsed_url.m_hostname);
            m_request_writer.write_header("User-agent", "co_http");
            m_request_writer.write_header("Accept", "*/*");
            if (!m_request.body.empty()) {
                m_request_writer.write_header(
                    "Content-length", std::to_string(m_request.body.size()));
            }
            m_request_writer.end_header();
            if (!m_request.body.empty()) {
                m_request_writer.write_body(m_request.body);
            }
            http_response response;
            // fmt::println("正在写入请求...");
            return do_write(m_request_writer.buffer());
        }

        void do_write(bytes_const_view buffer) 
        {
            return m_conn.async_write(buffer, [self = shared_from_this(), buffer](expected<size_t> ret) {
                if(ret.error()) 
                    return self->m_cb(ret.error(), {});
                auto n = ret.value();
                if(buffer.size() == n) 
                {
                    self->m_request_writer.reset_state();
                    return self->do_read();
                }        
                return self->do_write(buffer.subspan(n));
            });
        }

        void do_read() 
        {
            return m_conn.async_read(m_buf, [self = shared_from_this()](expected<size_t> ret) {
                if(ret.error()) 
                    return self->m_cb(ret.error(), {});

                auto n = ret.value();
                if(n == 0) 
                    return;

                self->m_response_parser.push_chunk(self->m_buf.subspan(0, n));
                if(!self->m_response_parser.request_finished()) 
                {
                    return self->do_read();
                } else {
                    return self->do_finish();
                }
            });
        }

        void do_finish() 
        {
            if(m_stop.stop_request()) 
            {
                return m_cb(-ECANCELED, {});
            }

            auto response = http_response{
                m_response_parser.status(),
                std::move(m_response_parser.body()),
                std::move(m_response_parser.headers())
            };

            m_response_parser.reset_state();
            return m_cb(0, response);
        }

    };

    std::map<std::string, http_connection_handler::pointer> m_conn_pool;

    /* 外部请求接口 */
    void do_request(http_request request, callback<expected<int>, http_response const&> cb, stop_source stop = {})
    {
        auto parsed_url = _http_url_parser(request.url);
        auto key = parsed_url.m_scheme + parsed_url.m_hostname;
        auto it = m_conn_pool.find(key);
        http_connection_handler::pointer conn;
        if(it != m_conn_pool.end()) 
        {
            conn = it->second;
        } else {
            conn = http_connection_handler::make();
            m_conn_pool.insert({key, conn});
        }
        request.url = parsed_url.m_url;
        conn->do_request(std::move(request), std::move(parsed_url), std::move(cb), stop);
    }
};