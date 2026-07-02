#pragma once
#include "packet.hpp"
#include <functional>
#include <string>
#include <atomic>
#include <vector>

struct CaptureOptions {
    std::string interface;
    std::string bpf_filter;
    int         snaplen    = SNAPLEN;
    int         timeout_ms = 1;
    bool        promisc    = true;
};

using PacketCallback = std::function<void(const Packet&)>;

class Sniffer {
public:
    explicit Sniffer(const CaptureOptions& opts);
    ~Sniffer();

    Sniffer(const Sniffer&)            = delete;
    Sniffer& operator=(const Sniffer&) = delete;

    void start(PacketCallback cb);
    void stop();

    const std::string& active_interface() const { return active_iface_; }

private:
    CaptureOptions    opts_;
    void*             handle_  = nullptr;
    std::atomic<bool> running_{ false };
    std::string       active_iface_;

    static void dispatch(uint8_t* user,
                         const struct pcap_pkthdr* hdr,
                         const uint8_t* pkt);
};

std::vector<std::string> list_interfaces();
