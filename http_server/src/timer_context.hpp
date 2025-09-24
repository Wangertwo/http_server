#pragma once

#include <callback.hpp>
#include <stop_source.hpp>

#include <map>
#include <chrono>

struct timer_context 
{
    struct _timer_entry 
    {
        callback<> m_cb;
        stop_source m_stop;
    };

    timer_context() = default;
    timer_context(timer_context &&) = delete;

    std::multimap<std::chrono::steady_clock::time_point, _timer_entry> m_timer_heap;
    void set_timeout(std::chrono::steady_clock::duration dt, callback<> cb, stop_source timer_stop = {}) 
    {
        auto expire_time = std::chrono::steady_clock::now() + dt;
        auto it = m_timer_heap.insert({expire_time, _timer_entry{std::move(cb), timer_stop}});
        timer_stop.set_stop_callback([this, it] {
            auto cb = std::move(it->second.m_cb);
            m_timer_heap.erase(it);
            cb();
        });
    }

    std::chrono::steady_clock::duration duration_to_next_timer() 
    {
        while(!m_timer_heap.empty()) 
        {
            auto it = m_timer_heap.begin();
            auto now = std::chrono::steady_clock::now();
            if(it->first <= now) 
            {
                it->second.m_stop.clear_stop_callback();
                auto cb = std::move(it->second.m_cb);
                m_timer_heap.erase(it);
                cb();
            } else {
                return it->first - now;
            }
        }
        return std::chrono::nanoseconds(-1);
    }

    bool is_empty() const
    {
        return m_timer_heap.empty();
    }
};
