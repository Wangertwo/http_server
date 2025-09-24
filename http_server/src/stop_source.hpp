#pragma once

struct stop_source 
{
    struct _control 
    {
        bool m_stop{false};
        callback<> m_cb;
    };

    std::shared_ptr<_control> m_control;

    stop_source() = default;
    stop_source(std::in_place_t) : m_control(std::make_shared<_control>()) {}
    
    static stop_source make() {
        return stop_source(std::in_place);
    }

    bool stop_possible() const noexcept 
    {
        return !m_control->m_stop;
    }

    bool stop_request() const noexcept 
    {
        return m_control && m_control->m_stop;
    }

    void set_stop_callback(callback<> cb) const noexcept
    {
        if(!m_control) 
        {
            return;
        }
        m_control->m_cb = std::move(cb);
    }

    void clear_stop_callback() const noexcept 
    {
        if(!m_control) 
        {
            return;
        }
        m_control->m_cb = nullptr;
    }    

    void request_stop() const noexcept 
    {
        if(!m_control) 
        {
            return;
        }
        if(m_control->m_cb) 
        {
            m_control->m_stop = true;
            m_control->m_cb();
            m_control->m_cb = nullptr;
        }
    }
};
