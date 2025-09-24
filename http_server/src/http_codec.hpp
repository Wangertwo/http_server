#pragma once

#include <algorithm>

#include "bytes_buffer.hpp"

using simple_map = std::map<std::string, std::string>;

struct http11_header_parser
{
    std::string m_header;
    std::string m_body;
    std::string m_header_line;
    simple_map m_headers;
    bool m_read_header_finished = false;
    
    void reset_state() 
    {
        m_header.clear();
        m_body.clear();
        m_header_line.clear();
        m_headers.clear();
        m_read_header_finished = false;
    }

    bool header_finished() const
    {
        return m_read_header_finished;
    }

    void _extract_headers() 
    {
        std::size_t pos = m_header.find("\r\n");
        m_header_line = m_header.substr(0, pos);
        while(pos != std::string::npos) 
        {
            pos += 2;
            std::size_t next_pos = m_header.find("\r\n", pos);
            std::size_t line_len;
            if(next_pos != std::string::npos) 
            {
                line_len = next_pos - pos;
            }
            else
            {
                line_len = m_header.size() - pos;
            }
    
            if(pos + line_len > m_header.size())
            {
                break; // Prevent out_of_range
            }
    
            std::string line = m_header.substr(pos, line_len);
            std::size_t colon = line.find(": ");
            if(colon != std::string::npos) 
            {
                std::string key = line.substr(0, colon);
                std::string value = line.substr(colon + 2);
                std::transform(key.begin(), key.end(), key.begin(), [](char c) -> char
                {
                    if('A' <= c && c <= 'Z') 
                    {
                        c += 'a' - 'A';
                        return c;
                    }
                    return c;
                });
                m_headers.insert_or_assign(key, value);
            }
            pos = next_pos;
        }
    }

    void push_chunk(std::string_view chunk) 
    {
        if(!m_read_header_finished) 
        {
            m_header.append(chunk);
            auto pos = m_header.find("\r\n\r\n");
            if(pos != std::string::npos) 
            {
                m_read_header_finished = true;
                m_body = m_header.substr(pos + 4);
                m_header.resize(pos);
                _extract_headers();
            } 
        }
    }

    std::string& extract_header() 
    {
        return m_header;
    }

    std::string& extract_body() 
    {
        return m_body;
    }

    simple_map& headers_kv() 
    {
        return m_headers;
    }

    std::string& header_line() 
    {
        return m_header_line;
    }
};

template <class http_header_parser = http11_header_parser>
struct http_base_parser
{
    http_header_parser m_parser;
    bool m_read_body_finished;
    std::size_t m_content_length;

    void reset_state() 
    {
        m_parser.reset_state();
        m_content_length = 0;
        m_read_body_finished = false;
    }

    simple_map& headers() 
    {
        return m_parser.headers_kv();
    }

    std::string& body() 
    {
        return m_parser.extract_body();
    }

    std::string& header() 
    {
        return m_parser.extract_header();
    }

    bool header_finished() 
    {
        return m_parser.header_finished();
    }

    bool request_finished() 
    {
        return m_read_body_finished;
    }

    /* GET / http/1.1 */
    /* http/1.1 200 OK */
    std::string _headerline_first() 
    {
        auto& header_line = m_parser.header_line();
        std::size_t pos = header_line.find(" ");
        if(pos == std::string::npos) 
        {
            return "";
        }
        return header_line.substr(0, pos);
    }

    std::string _headerline_second() 
    {
        auto& header_line = m_parser.header_line();
        std::size_t pos = header_line.find(" ");
        if(pos == std::string::npos) 
        {
            return "";
        }
        std::size_t next_pos = header_line.find(" ", pos + 1);
        if(next_pos == std::string::npos) 
        {
            return "";
        }
        return header_line.substr(pos + 1, next_pos - (pos + 1));
    }

    std::string _headerline_third() 
    {
        auto& header_line = m_parser.header_line();
        std::size_t pos = header_line.rfind(" ");
        if(pos == std::string::npos) 
        {
            return "";
        }
        return header_line.substr(pos);
    }

    std::size_t _extract_content_length() 
    {
        auto map = m_parser.headers_kv();
        auto it = map.find("content-length");
        if(it == map.end()) 
        {
            return 0;
        }
        try {
            return std::stoi(it->second);
        } catch(...) {
            return 0;
        }
    }

    void push_chunk(std::string_view chunk) 
    {
        if(!header_finished()) 
        {
            m_parser.push_chunk(chunk);
            if(header_finished()) 
            {
                m_content_length = _extract_content_length();
                if(body().size() >= m_content_length) 
                {
                    m_read_body_finished = true;
                    body().resize(m_content_length);
                }
            }
        } 
        else 
        {
            body().append(std::string(chunk));
            if(body().size() >= m_content_length) 
            {
                m_read_body_finished = true;
                body().resize(m_content_length);
            }
        }
    }
};


template <class http_request_parser = http11_header_parser>
struct request_parser : public http_base_parser<http_request_parser>
{
    std::string method() 
    {
        return this->_headerline_first();
    }

    std::string url() 
    {
        return this->_headerline_second();
    }

    std::string version() 
    {
        return this->_headerline_third();
    }
};

template <class http_request_parser = http11_header_parser>
struct response_parser : public http_base_parser<http_request_parser> 
{
    std::string version() 
    {
        return this->_headerline_first();
    }

    int status() 
    {
        try {
            return std::stoi(this->_headerline_second());
        } catch(...) {
            throw std::runtime_error("status convert error");
        }
    }

    std::string status_string() 
    {
        return this->_headerline_third();
    }
};

struct http11_header_writer 
{
    bytes_buffer m_buffer;

    void reset_state() 
    {
        m_buffer.clear();
    }

    bytes_buffer& buffer() 
    {
        return m_buffer;    
    }

    void begin_header(std::string_view first, std::string_view second, std::string_view third) 
    {
        m_buffer.append(first);
        m_buffer.append_literial(" ");
        m_buffer.append(second);
        m_buffer.append_literial(" ");
        m_buffer.append(third);
    }

    void write_header(std::string_view key, std::string_view value) 
    {
        m_buffer.append_literial("\r\n");
        m_buffer.append(key);
        m_buffer.append_literial(": ");
        m_buffer.append(value);
    }

    void end_header() {
        m_buffer.append_literial("\r\n\r\n");
    }
};

template <class HeaderWriter = http11_header_writer>
struct _header_writer_base 
{
    HeaderWriter m_header_writer;
    void _begin_header(std::string_view first, std::string_view second, std::string_view third) 
    {
        m_header_writer.begin_header(first, second, third);
    }

    void write_header(std::string_view key, std::string_view value) 
    {
        m_header_writer.write_header(key, value);
    }

    void end_header() {
        m_header_writer.end_header();
    }

    void reset_state() 
    {
        m_header_writer.reset_state();
    }

    bytes_buffer& buffer() 
    {
        return m_header_writer.buffer();
    }

    void write_body(std::string_view body) 
    {
        m_header_writer.buffer().append(body);
    }
 };

template <class HeaderWriter = http11_header_writer>
struct response_writer : _header_writer_base<HeaderWriter>
{
    void begin_header(int status) {
        this->_begin_header("HTTP/1.1", std::to_string(status), "OK");
    }
};

template <class HeaderWriter = http11_header_writer>
struct request_writer : _header_writer_base<HeaderWriter>
{
    void begin_header(std::string_view method, std::string_view url) {
        this->_begin_header(method, url, "HTTP/1.1");
    }
};
