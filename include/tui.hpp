#pragma once
#include "packet.hpp"
#include "cli.hpp"
#include <deque>
#include <string>
#include <cstdint>
#include <ctime>
#include <atomic>
#include <mutex>

struct DisplayRow {
    std::string proto;
    std::string src;
    std::string dst;
    std::string info;
    std::string service;
    uint32_t    length;
    std::time_t ts;
};

class Tui {
public:
    explicit Tui(const CliOptions& opts, const std::string& iface,
                 const std::string& filter);
    ~Tui();

    void push(const Packet& pkt);

    int  run(int limit);

    bool done() const;
    void set_done();

private:
    void draw();
    void draw_header();
    void draw_table();
    void draw_footer();
    void handle_key(int ch);

    const CliOptions& opts_;
    std::string iface_;
    std::string filter_;

    std::deque<DisplayRow> rows_;
    std::mutex              rows_mtx_;

    std::atomic<int>      total_{ 0 };
    std::atomic<int>      dns_cnt_{ 0 };
    std::atomic<int>      http_cnt_{ 0 };
    std::atomic<int>      tls_cnt_{ 0 };
    std::atomic<int>      tcp_cnt_{ 0 };
    std::atomic<int>      udp_cnt_{ 0 };
    std::atomic<int>      icmp_cnt_{ 0 };
    std::atomic<int>      arp_cnt_{ 0 };
    std::atomic<int>      other_cnt_{ 0 };
    std::atomic<uint64_t> bytes_{ 0 };

    std::atomic<bool>     done_{ false };

    int scroll_  = 0;
    int max_rows_= 0;

    static constexpr int MAX_HISTORY = 2000;
};
