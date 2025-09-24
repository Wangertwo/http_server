#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <unistd.h>
#include <string>
#include <iostream>
#include <utility>
#include <cstring>
#include <vector>
#include <thread>
#include <string_view>
#include <algorithm>
#include <map>


/* 错误处理 */
std::error_category const& gai_category()
{
    struct gai_category final: std::error_category 
    {
        const char* name() const noexcept override 
        {
            return "gaiaddrinfo";
        }

        std::string message(int err) const noexcept override 
        {
            return gai_strerror(err);
        }
    };
    static gai_category instance;
    return instance;
}

template <int Expect = 0, class T>
int check_error(const char* what, T res) 
{
    if(res == -1) 
    {
        if constexpr (Expect != 0) 
        {
            if(errno == Expect) 
            {
                return -1;
            }
        }
        std::cout << stderr << what << ": " << res << std::endl;
        auto ec = std::error_code(errno, std::system_category());
        throw std::system_error(ec, what);
    }   
    return res;
}

#define FILE_LINE_IMPL_2(file, line) " In " file ":" #line ": "
#define FILE_LINE_IMPL(file, line) FILE_LINE_IMPL_2(file, line) 
#define FILE_LINE() FILE_LINE_IMPL(__FILE__, __LINE__)   
#define CHECK_CALL_EXPECT(expect, func, ...) check_error<expect>(FILE_LINE() #func, func(__VA_ARGS__))
#define CHECK_CALL(func, ...) check_error(FILE_LINE() #func, func(__VA_ARGS__))

/* socket地址解析器 */
struct socket_address_resolver 
{

struct socket_address_fatptr 
{
    struct sockaddr* m_addr;
    socklen_t m_addrlen;
};

struct socket_resolved_entry 
{
    struct addrinfo* m_entry = nullptr;

    socket_address_fatptr get_address() const
    {
        return {m_entry->ai_addr, m_entry->ai_addrlen};
    }

    int create_socket() const
    {
        return CHECK_CALL(socket, m_entry->ai_family, m_entry->ai_socktype, m_entry->ai_protocol);
    }

    int create_socket_and_bind() const 
    {
        int socketfd = create_socket();
        socket_address_fatptr addr = get_address();
        CHECK_CALL(bind, socketfd, addr.m_addr, addr.m_addrlen);
        return socketfd;
    }

    bool next_entry()  
    {
        m_entry = m_entry->ai_next;
        if(m_entry == nullptr) 
        {
            return false;
        }
        return true;
    }
};

struct socket_resolver 
{
    struct addrinfo* m_entry = nullptr;

    void resolve(const std::string& name, const std::string& service) 
    {
        auto err = getaddrinfo(name.c_str(), service.c_str(), NULL, &m_entry);
        if(err != 0) 
        {
            auto ec = std::error_code(errno, gai_category());
            throw std::system_error(ec, name + ":" + service);
        }
    } 

    socket_resolved_entry first_entry() 
    {
        return {m_entry};
    }

    socket_resolver() = default;

    socket_resolver(socket_resolver&& that) 
        : m_entry(std::exchange(that.m_entry, nullptr)) {}

    ~socket_resolver() 
    {
        if(m_entry) 
        {
            freeaddrinfo(m_entry);
        }
    }
};

struct socket_address_storage 
{
    union 
    {
        struct sockaddr m_addr;
        struct sockaddr_storage m_addr_storage;   
    };
    socklen_t m_addrlen = sizeof(struct sockaddr_storage);

    operator socket_address_fatptr() 
    {
        return {&m_addr, m_addrlen};
    }
};
};

/* 缓冲区 */
struct bytes_const_view 
{
    const char* m_data;
    std::size_t m_size;

    const char* data() const noexcept
    {
        return m_data;
    }

    std::size_t size() const noexcept
    {
        return m_size;
    }

    const char* begin() const noexcept 
    {
        return data();
    }

    const char* end() const noexcept 
    {
        return data() + size();
    }

    bytes_const_view subspan(std::size_t start, std::size_t len = std::size_t(-1)) 
    {
        if(start > size()) 
        {
            throw std::out_of_range("bytes_const_view::subspan");
        }

        if(len > size() - start) 
        {
            len = size() - start;
        }

        return {data() + start, len};
    }

    operator std::string_view() const noexcept 
    {
        return std::string_view{data(), size()};
    }
};

struct bytes_view 
{
    char* m_data;
    std::size_t m_size;

    char* data() noexcept
    {
        return m_data;
    }

    std::size_t size() noexcept
    {
        return m_size;
    }

    char* begin() noexcept 
    {
        return data();
    }

    char* end() noexcept 
    {
        return data() + size();
    }

    bytes_view subspan(std::size_t start, std::size_t len = std::size_t(-1)) 
    {
        if(start > size()) 
        {
            throw std::out_of_range("bytes_const_view::subspan");
        }

        if(len > size() - start) 
        {
            len = size() - start;
        }

        return {data() + start, len};
    }

    operator std::string_view() noexcept 
    {
        return std::string_view{data(), size()};
    }

    operator bytes_const_view() noexcept 
    {
        return bytes_const_view{data(), size()};
    }
};

struct bytes_buffer {
    std::vector<char> m_data;

    bytes_buffer() = default;
    bytes_buffer(bytes_buffer &&) = default;
    bytes_buffer &operator=(bytes_buffer &&) = default;
    explicit bytes_buffer(bytes_buffer const &) = default;

    explicit bytes_buffer(size_t n) : m_data(n) {}

    char const *data() const noexcept {
        return m_data.data();
    }

    char *data() noexcept {
        return m_data.data();
    }

    size_t size() const noexcept {
        return m_data.size();
    }

    char const *begin() const noexcept {
        return data();
    }

    char *begin() noexcept {
        return data();
    }

    char const *end() const noexcept {
        return data() + size();
    }

    char *end() noexcept {
        return data() + size();
    }

    bytes_const_view subspan(size_t start, size_t len) const {
        return operator bytes_const_view().subspan(start, len);
    }

    bytes_view subspan(size_t start, size_t len) {
        return operator bytes_view().subspan(start, len);
    }

    operator bytes_const_view() const noexcept {
        return bytes_const_view{m_data.data(), m_data.size()};
    }

    operator bytes_view() noexcept {
        return bytes_view{m_data.data(), m_data.size()};
    }

    operator std::string_view() const noexcept {
        return std::string_view{m_data.data(), m_data.size()};
    }

    void append(bytes_const_view chunk) {
        m_data.insert(m_data.end(), chunk.begin(), chunk.end());
    }

    void append(std::string_view chunk) {
        m_data.insert(m_data.end(), chunk.begin(), chunk.end());
    }

    template <size_t N>
    void append_literial(char const (&literial)[N]) {
        append(std::string_view{literial, N - 1});
    }

    void clear() {
        m_data.clear();
    }

    void resize(size_t n) {
        m_data.resize(n);
    }

    void reserve(size_t n) {
        m_data.reserve(n);
    }
};

template <size_t N>
struct static_bytes_buffer {
    std::array<char, N> m_data;

    char const *data() const noexcept {
        return m_data.data();
    }

    char *data() noexcept {
        return m_data.data();
    }

    static constexpr size_t size() noexcept {
        return N;
    }

    operator bytes_const_view() const noexcept {
        return bytes_const_view{m_data.data(), N};
    }

    operator bytes_view() noexcept {
        return bytes_view{m_data.data(), N};
    }

    operator std::string_view() const noexcept {
        return std::string_view{m_data.data(), m_data.size()};
    }
};


std::vector<std::thread> pool;
using simple_map = std::map<std::string, std::string>;

struct http11_header_parser
{
    std::string m_header;
    std::string m_body;
    std::string m_header_line;
    simple_map m_headers;
    bool m_read_header_finished = false;
    
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

    std::size_t status() 
    {
        return this->_headerline_second();
    }

    std::string status_string() 
    {
        return this->_headerline_third();
    }
};

struct response_writer 
{
    bytes_buffer m_buffer;

    void begin_write(std::size_t status) 
    {
        m_buffer.append("HTTP/1.1 ");
        m_buffer.append(std::to_string(status));
        m_buffer.append(" OK\r\n");
    }

    void end_write() 
    {
        m_buffer.append("\r\n");
    }

    void write_chunk(std::string_view key, std::string_view value) 
    {
        m_buffer.append(key);
        m_buffer.append(": ");
        m_buffer.append(value);
        m_buffer.append("\r\n");
    }

    bytes_buffer buffer() 
    {
        return std::move(m_buffer);
    }
};

void server() 
{
    socket_address_resolver::socket_resolver resolver;
    resolver.resolve("127.0.0.1", "8080");
    auto entry = resolver.first_entry();
    int listenfd = entry.create_socket_and_bind();
    std::cout << "正在监听：" << "127.0.0.1" << " 8080" << std::endl;
    CHECK_CALL(listen, listenfd, SOMAXCONN);
    while(true) 
    {
        socket_address_resolver::socket_address_storage addr;
        int connid = CHECK_CALL(accept, listenfd, &addr.m_addr, &addr.m_addrlen);
        pool.emplace_back([connid] 
            {
                while(true) 
                {
                    bytes_buffer buf(1024);
                    request_parser req_parser;
                    do {
                        ssize_t n = CHECK_CALL(read, connid, buf.data(), buf.size());
                        if(n == 0) 
                        {
                            //读到关闭连接的请求
                            goto quit;
                        }
                        req_parser.push_chunk(buf.subspan(0, n));
                    } while (!req_parser.request_finished());

                    auto req = req_parser.header();
                    auto res = req_parser.body();
                    response_writer writer;
                    writer.begin_write(200);
                    writer.write_chunk("Server", "co_http");
                    writer.write_chunk("Connection", "keep-alive");
                    writer.write_chunk("Content-Length", std::to_string(res.size()));
                    writer.end_write();

                    auto res_header = writer.buffer();
                    if(CHECK_CALL_EXPECT(EPIPE, write, connid, res_header.data(), res_header.size()) == -1)
                        break;
                    if(CHECK_CALL_EXPECT(EPIPE, write, connid, res.data(), res.size()) == -1)
                        break;
                }
            quit:
                std::cout << "关闭连接" << std::endl;
                close(connid);
            });
    }
}

int main() 
{
    try {
        server();
    } catch (std::system_error const& se) {
        std::cout << "错误：" << se.what() << std::endl;
    }

    for(auto&& t : pool) 
    {
        t.join();
    }
    return 0;
}