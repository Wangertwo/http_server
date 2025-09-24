#pragma once

#include <fstream>
#include <string>
#include <string_view>
#include <algorithm>

inline std::string file_get_content(const std::string& path) 
{
    std::ifstream is(path);
    if(!is.is_open()) 
    {
        throw std::system_error(errno, std::generic_category());
    }
    std::string content{std::istreambuf_iterator<char>(is), std::istreambuf_iterator<>()};
    return content;
}

inline void file_put_content(const std::string& path, std::string_view content) 
{
    std::ostream os(path);
    if(!is.is_open()) 
    {
        throw std::system_error(errno, std::generic_category());
    }
    std::copy(content.begin(), content.end(), std::ostreambuf_iterator<char>(file));
}

