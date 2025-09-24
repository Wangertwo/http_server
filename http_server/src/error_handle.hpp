#pragma once
#include <system_error>
#include <iostream>
#include <cerrno>
#include <cstring>
#include <netdb.h>

/* ¥ÌŒÛ¥¶¿Ì */
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
#define CONVERT_CALL(type, func, ...) convert_error<type>(func(__VA_ARGS__))