#pragma once

#include "timer_context.hpp"
#include "error_handle.hpp"
#include "expected.hpp"
#include "callback.hpp"
#include "bytes_buffer.hpp"

#include <cerrno>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <unistd.h>
#include <utility>
#include <array>

struct io_context : timer_context
{
    int m_epollfd;
    size_t m_epcount = 0;

    inline static thread_local io_context* instance = nullptr;
    io_context() :m_epollfd(CHECK_CALL(epoll_create1, 0)) 
    {
        instance = this;
    } 

    void join() 
    {
        std::array<struct epoll_event, 128> events;
        while (!is_empty()) {
            std::chrono::nanoseconds dt = duration_to_next_timer();
            int timeout_ms = -1;
            if (dt.count() >= 0) 
                timeout_ms = dt.count() / 1'000'000;

            int ret = convert_error(epoll_pwait(m_epollfd, events.data(), events.size(),
                                            timeout_ms, nullptr)).expect("epoll_pwait");
            for (int i = 0; i < ret; ++i) {
                auto cb = callback<>::from_address(events[i].data.ptr);
                cb();
                --m_epcount;
            }
        }
    }
    
    ~io_context() 
    {
        close(m_epollfd);
        instance = nullptr;
    }

    static io_context& get() 
    {
        assert(instance);
        return *instance;
    }

    bool is_empty() 
    {
        return timer_context::is_empty() && m_epcount == 0;
    }
};

/* socket地址解析器 */
struct address_resolver 
{
    struct address_ref 
    {
        struct sockaddr* m_addr;
        socklen_t m_addrlen;
    };

    struct address {
        union {
            struct sockaddr m_addr;
            struct sockaddr_storage m_addr_storage;
        };

        socklen_t m_addrlen = sizeof(struct sockaddr_storage);

        operator address_ref() {
            return {&m_addr, m_addrlen};
        }
    };

    struct address_info
    {
        struct addrinfo* m_entry = nullptr;

        address_ref get_address() const 
        {
            return {m_entry->ai_addr, m_entry->ai_addrlen};
        }

        int create_socket() const
        {
            return CHECK_CALL(socket, m_entry->ai_family, m_entry->ai_socktype, m_entry->ai_protocol);
        }

        bool next_entry()  
        {
            m_entry = m_entry->ai_next;
            if(m_entry == nullptr) 
                return false;
            return true;
        }
    };

    struct addrinfo* m_head = nullptr;

    address_info resolve(const std::string& name, const std::string& service) 
    {
        auto err = getaddrinfo(name.c_str(), service.c_str(), NULL, &m_head);
        if(err != 0) 
        {
            auto ec = std::error_code(errno, gai_category());
            throw std::system_error(ec, name + ":" + service);
        }
        return {m_head};
    } 

    address_resolver() = default;

    address_resolver(address_resolver &&that) : m_head(that.m_head) 
    {
        that.m_head = nullptr;
    }

    ~address_resolver() 
    {
        if (m_head) 
            freeaddrinfo(m_head);
    }
};

struct file_descriptor 
{
    int m_fd = -1;
    
    file_descriptor() = default;

    file_descriptor(int fd) : m_fd(fd) {}
    file_descriptor(file_descriptor && that) noexcept 
        : m_fd(that.m_fd)
    {
        that.m_fd = -1;
    }

    file_descriptor &operator=(file_descriptor &&that) noexcept 
    {
        std::swap(m_fd, that.m_fd);
        return *this;
    }

    ~file_descriptor() 
    {
        if(m_fd == -1)
            return;
        close(m_fd);
    }
};

struct async_file : file_descriptor
{
    async_file() = default;

    explicit async_file(int fd) noexcept: file_descriptor(fd) 
    {
        auto flags = CHECK_CALL(fcntl, fd, F_GETFL);
        flags |= O_NONBLOCK; 
        CHECK_CALL(fcntl, fd, F_SETFL, flags);

        struct epoll_event event;
        event.events = EPOLLET; /* 边缘触发 */
        event.data.ptr = nullptr;
        epoll_ctl(io_context::get().m_epollfd, EPOLL_CTL_ADD, fd, &event);
    }

    void _epoll_callback(callback<> resume, uint32_t events, stop_source stop) 
    {
        struct epoll_event event;
        event.events = events;
        event.data.ptr = resume.get_address(); /* ptr = &resume */
        epoll_ctl(io_context::get().m_epollfd, EPOLL_CTL_MOD, m_fd, &event);
        ++io_context::get().m_epcount;
        stop.set_stop_callback([resume_ptr = resume.leak_address()] {
            callback<>::from_address(resume_ptr)();
        });
    }

    void async_read(bytes_view buf, callback<expected<size_t>> cb, stop_source stop_io = {}) 
    {
        if(stop_io.stop_request()) 
        {
            stop_io.clear_stop_callback();
            return cb(-ECANCELED); /* 该操作被取消了 */
        }

        expected<size_t> ret = CONVERT_CALL(size_t, read, m_fd, buf.data(), buf.size());
        if(!ret.is_error(EAGAIN)) 
        {
            stop_io.clear_stop_callback();
            return cb(ret);
        }
        
        return _epoll_callback([this, buf, callback = std::move(cb), stop_io] () mutable {
            return async_read(buf, std::move(callback), stop_io);
        }, EPOLLIN | EPOLLET | EPOLLONESHOT | EPOLLERR, stop_io);
    }

    void async_write(bytes_const_view buf, callback<expected<size_t>> cb, stop_source stop_io = {}) 
    {
        if(stop_io.stop_request()) 
        {
            stop_io.clear_stop_callback();
            return cb(-ECANCELED);
        }

        expected<size_t> ret = CONVERT_CALL(size_t, write, m_fd, buf.data(), buf.size());
        if(!ret.is_error(EAGAIN)) 
        {
            stop_io.clear_stop_callback();
            return cb(ret);
        }
        
        return _epoll_callback([this, buf, callback = std::move(cb), stop_io] () mutable {
            return async_write(buf, std::move(callback), stop_io);
        }, EPOLLOUT | EPOLLET | EPOLLONESHOT | EPOLLERR, stop_io);
    }

    void async_accept(address_resolver::address& addr, callback<expected<int>> cb, stop_source stop_io = {}) 
    {
        if(stop_io.stop_request()) 
        {
            stop_io.clear_stop_callback();
            return cb(-ECANCELED);
        }

        expected<int> ret = CONVERT_CALL(int, accept, m_fd, &addr.m_addr, &addr.m_addrlen);
        if(!ret.is_error(EAGAIN)) 
        {
            stop_io.clear_stop_callback();
            cb(ret);
            return;
        }

        return _epoll_callback([this, addr, callback = std::move(cb), stop_io] () mutable {
            return async_accept(addr, std::move(callback), stop_io);
        }, EPOLLIN | EPOLLET | EPOLLONESHOT | EPOLLERR , stop_io);
    }

    static async_file async_bind(address_resolver::address_info& addr_info) 
    {
        async_file sock{addr_info.create_socket()};
        auto server_addr = addr_info.get_address();
        int on = 1;
        setsockopt(sock.m_fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
        setsockopt(sock.m_fd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));
        convert_error(bind(sock.m_fd, server_addr.m_addr, server_addr.m_addrlen))
            .expect("bind");
        convert_error(listen(sock.m_fd, SOMAXCONN)).expect("listen");
        return sock;
    }

    void async_connect(address_resolver::address_info const &addr,
                       callback<expected<int>> cb, stop_source stop = {}) {
        if (stop.stop_request()) {
            stop.clear_stop_callback();
            return cb(-ECANCELED);
        }
        auto addr_ptr = addr.get_address();
        auto ret =
            convert_error(connect(m_fd, addr_ptr.m_addr, addr_ptr.m_addrlen));
        if (!ret.is_error(EINPROGRESS)) {
            stop.clear_stop_callback();
            return cb(ret);
        }
        return _epoll_callback(
            [this, cb = std::move(cb), stop]() mutable {
                if (stop.stop_request()) {
                    stop.clear_stop_callback();
                    return cb(-ECANCELED);
                }
                int ret;
                socklen_t ret_len = sizeof(ret);
                convert_error(
                    getsockopt(m_fd, SOL_SOCKET, SO_ERROR, &ret, &ret_len))
                    .expect("getsockopt");
                if (ret > 0) {
                    ret = -ret;
                }
                stop.clear_stop_callback();
                return cb(ret);
            },
            EPOLLOUT | EPOLLERR | EPOLLONESHOT, stop);
    }

    ~async_file() 
    {
        if(m_fd == -1)
            return;
        epoll_ctl(io_context::get().m_epollfd, EPOLL_CTL_DEL, m_fd, NULL);
    }

    async_file(async_file &&) = default;
    async_file &operator=(async_file &&) = default;

    explicit operator bool() const noexcept
    {
        return m_fd != -1;
    }
};