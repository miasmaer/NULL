#pragma once
#include <string>
#include <cstdint>

static constexpr int SNAPLEN = 1500;

enum class Proto : uint8_t {
    UNKNOWN = 0,
    TCP,
    UDP,
    ICMP,
    ICMPV6,
    IGMP,
    GRE,
    ESP,
    AH,
    SCTP,
    OSPF,
    ARP,
    OTHER,
};

struct Packet {
    std::string src_ip;
    std::string dst_ip;
    Proto       proto    = Proto::UNKNOWN;
    uint16_t    src_port = 0;
    uint16_t    dst_port = 0;
    uint32_t    length   = 0;
    bool        is_ipv6  = false;
    std::string hostname;
    std::string http_method;
    std::string http_path;

    bool is_dns()   const { return src_port == 53  || dst_port == 53;  }
    bool is_http()  const { return dst_port == 80  || src_port == 80;  }
    bool is_https() const { return dst_port == 443 || src_port == 443; }

    std::string proto_str() const;
    std::string service()   const;
};

bool parse_packet(const uint8_t* data, uint32_t caplen, Packet& out);
