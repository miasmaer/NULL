#include "packet.hpp"
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <cstring>
#include <unordered_map>

#ifndef ETH_P_IPV6
#define ETH_P_IPV6 0x86DD
#endif
#ifndef ETH_P_ARP
#define ETH_P_ARP 0x0806
#endif
#ifndef IPPROTO_SCTP
#define IPPROTO_SCTP 132
#endif
#ifndef IPPROTO_OSPFIGP
#define IPPROTO_OSPFIGP 89
#endif

static std::string ip4_str(uint32_t addr_net)
{
    char buf[INET_ADDRSTRLEN];
    ::inet_ntop(AF_INET, &addr_net, buf, sizeof(buf));
    return buf;
}

static std::string ip6_str(const uint8_t* addr)
{
    char buf[INET6_ADDRSTRLEN];
    ::inet_ntop(AF_INET6, addr, buf, sizeof(buf));
    return buf;
}

static void parse_arp(const uint8_t* data, uint32_t len, Packet& pkt)
{
    if (len < 28) return;
    uint16_t ptype = (uint16_t(data[2]) << 8) | data[3];
    if (ptype != 0x0800) return;
    uint32_t spa, tpa;
    std::memcpy(&spa, data + 14, 4);
    std::memcpy(&tpa, data + 24, 4);
    pkt.src_ip = ip4_str(spa);
    pkt.dst_ip = ip4_str(tpa);
}

static void parse_http(const uint8_t* payload, uint32_t plen, Packet& pkt)
{
    if (plen < 8) return;

    static const char* methods[] = {
        "GET ", "POST ", "PUT ", "DELETE ",
        "HEAD ", "OPTIONS ", "PATCH ", "CONNECT "
    };
    bool found = false;
    for (auto* m : methods) {
        if (std::strncmp(reinterpret_cast<const char*>(payload),
                         m, std::strlen(m)) == 0) { found = true; break; }
    }
    if (!found) return;

    const char* text = reinterpret_cast<const char*>(payload);
    uint32_t    tlen = std::min(plen, uint32_t(1024));

    const char* sp1 = static_cast<const char*>(std::memchr(text, ' ', tlen));
    if (!sp1) return;
    pkt.http_method.assign(text, sp1 - text);

    const char* sp2 = static_cast<const char*>(
        std::memchr(sp1 + 1, ' ', tlen - (sp1 + 1 - text)));
    if (!sp2) return;
    pkt.http_path.assign(sp1 + 1, sp2 - sp1 - 1);

    static const char host_hdr[] = "\r\nHost: ";
    const char* hpos = std::strstr(text, host_hdr);
    if (hpos) {
        hpos += sizeof(host_hdr) - 1;
        const char* end = std::strstr(hpos, "\r\n");
        if (end) pkt.hostname.assign(hpos, end - hpos);
    }
}

static void parse_tls_sni(const uint8_t* data, uint32_t dlen, Packet& pkt)
{
    if (dlen < 5 || data[0] != 0x16) return;
    if (dlen < 43 || data[5] != 0x01) return;

    uint32_t off = 5 + 1 + 3 + 2 + 32;
    if (off >= dlen) return;

    uint8_t sid = data[off++];
    off += sid;
    if (off + 2 > dlen) return;

    uint16_t cs = (uint16_t(data[off]) << 8) | data[off+1];
    off += 2 + cs;
    if (off + 1 > dlen) return;

    off += data[off] + 1;
    if (off + 2 > dlen) return;

    uint16_t ext_total = (uint16_t(data[off]) << 8) | data[off+1];
    off += 2;
    uint32_t ext_end = std::min(off + uint32_t(ext_total), dlen);

    while (off + 4 <= ext_end) {
        uint16_t etype = (uint16_t(data[off]) << 8) | data[off+1];
        uint16_t elen  = (uint16_t(data[off+2]) << 8) | data[off+3];
        off += 4;
        if (etype == 0x0000) {
            if (off + 5 > ext_end) break;
            uint8_t  ntype = data[off+2];
            uint16_t nlen  = (uint16_t(data[off+3]) << 8) | data[off+4];
            off += 5;
            if (ntype == 0 && off + nlen <= ext_end)
                pkt.hostname.assign(reinterpret_cast<const char*>(data + off), nlen);
            break;
        }
        off += elen;
    }
}

static void parse_quic_sni(const uint8_t* data, uint32_t dlen, Packet& pkt)
{
    if (dlen < 6) return;

    if ((data[0] & 0x80) == 0) return;
    if ((data[0] & 0x30) != 0x00) return;
    uint32_t version = (uint32_t(data[1]) << 24) | (uint32_t(data[2]) << 16)
                     | (uint32_t(data[3]) << 8)  |  uint32_t(data[4]);
    if (version == 0) return;

    uint32_t off = 5;
    if (off >= dlen) return;
    uint8_t dcil = data[off++];
    off += dcil;
    if (off >= dlen) return;
    uint8_t scil = data[off++];
    off += scil;
    if (off >= dlen) return;
    uint8_t token_len_byte = data[off++];
    uint64_t token_len = 0;
    if ((token_len_byte & 0xC0) == 0x00) {
        token_len = token_len_byte & 0x3F;
    } else if ((token_len_byte & 0xC0) == 0x40) {
        if (off >= dlen) return;
        token_len = (uint64_t(token_len_byte & 0x3F) << 8) | data[off++];
    } else {
        return;
    }
    off += (uint32_t)token_len;
    if (off + 2 > dlen) return;
    uint8_t len_byte = data[off++];
    if ((len_byte & 0xC0) == 0x40) {
        off++;
    } else if ((len_byte & 0xC0) == 0x80) {
        off += 3;
    } else if ((len_byte & 0xC0) == 0xC0) {
        off += 7;
    }
    uint8_t pn_len = (data[0] & 0x03) + 1;
    off += pn_len;

    if (off >= dlen) return;
    const uint8_t* payload = data + off;
    uint32_t       plen    = dlen - off;
    for (uint32_t i = 0; i + 8 < plen; ++i) {
        if (payload[i] == 0x06) {
            for (uint32_t j = i + 1; j + 6 < plen; ++j) {
                if (payload[j] == 0x01) {
                    parse_tls_sni(payload + j - 1, plen - j + 1, pkt);
                    if (!pkt.hostname.empty()) return;
                }
            }
            break;
        }
    }
}

static void parse_dns(const uint8_t* data, uint32_t dlen, Packet& pkt)
{
    if (dlen < 13) return;
    if (data[2] & 0x80) return;

    uint16_t qdcount = (uint16_t(data[4]) << 8) | data[5];
    if (qdcount == 0) return;

    uint32_t off = 12;
    std::string name;
    name.reserve(64);

    while (off < dlen) {
        uint8_t llen = data[off++];
        if (llen == 0) break;
        if ((llen & 0xC0) == 0xC0) { ++off; break; }
        if (!name.empty()) name += '.';
        if (off + llen > dlen) break;
        name.append(reinterpret_cast<const char*>(data + off), llen);
        off += llen;
    }
    if (!name.empty()) pkt.hostname = std::move(name);
}

std::string Packet::proto_str() const
{
    switch (proto) {
        case Proto::TCP:    return "TCP";
        case Proto::UDP:    return "UDP";
        case Proto::ICMP:   return "ICMP";
        case Proto::ICMPV6: return "ICMPv6";
        case Proto::IGMP:   return "IGMP";
        case Proto::GRE:    return "GRE";
        case Proto::ESP:    return "ESP";
        case Proto::AH:     return "AH";
        case Proto::SCTP:   return "SCTP";
        case Proto::OSPF:   return "OSPF";
        case Proto::ARP:    return "ARP";
        case Proto::OTHER:  return "OTHER";
        default:            return "???";
    }
}

std::string Packet::service() const
{
    if (src_port == 0 && dst_port == 0) return proto_str();

    static const std::unordered_map<uint16_t, const char*> svc = {
        {20,"FTP-data"},{21,"FTP"},{22,"SSH"},{23,"Telnet"},
        {25,"SMTP"},{53,"DNS"},{67,"DHCP"},{68,"DHCP"},
        {80,"HTTP"},{110,"POP3"},{123,"NTP"},{143,"IMAP"},{443,"HTTPS"},
        {465,"SMTPS"},{500,"IKE"},{587,"SMTP"},{853,"DoT"},{993,"IMAPS"},
        {995,"POP3S"},{1723,"PPTP"},{3389,"RDP"},{4500,"IPSec-NAT"},{5353,"mDNS"},
        {5355,"LLMNR"},
    };
    uint16_t p  = dst_port ? dst_port : src_port;
    auto     it = svc.find(p);
    return it != svc.end() ? it->second : std::to_string(p);
}

static bool parse_l4(uint8_t protocol, const uint8_t* data, uint32_t caplen,
                     uint32_t l4off, Packet& pkt)
{
    uint32_t l7off = l4off;
    uint32_t l7len = 0;

    switch (protocol) {
        case IPPROTO_TCP: {
            pkt.proto = Proto::TCP;
            if (caplen < l4off + sizeof(tcphdr)) break;
            const auto* tcp = reinterpret_cast<const tcphdr*>(data + l4off);
            pkt.src_port    = ntohs(tcp->source);
            pkt.dst_port    = ntohs(tcp->dest);
            l7off = l4off + tcp->doff * 4u;
            l7len = (caplen > l7off) ? caplen - l7off : 0;
            break;
        }
        case IPPROTO_UDP: {
            pkt.proto = Proto::UDP;
            if (caplen < l4off + sizeof(udphdr)) break;
            const auto* udp = reinterpret_cast<const udphdr*>(data + l4off);
            pkt.src_port    = ntohs(udp->source);
            pkt.dst_port    = ntohs(udp->dest);
            l7off = l4off + sizeof(udphdr);
            l7len = (caplen > l7off) ? caplen - l7off : 0;
            break;
        }
        case IPPROTO_ICMP:
            pkt.proto = Proto::ICMP;
            break;
        case IPPROTO_ICMPV6:
            pkt.proto = Proto::ICMPV6;
            break;
        case IPPROTO_IGMP:
            pkt.proto = Proto::IGMP;
            break;
        case IPPROTO_GRE:
            pkt.proto = Proto::GRE;
            break;
        case IPPROTO_ESP:
            pkt.proto = Proto::ESP;
            break;
        case IPPROTO_AH:
            pkt.proto = Proto::AH;
            break;
        case IPPROTO_SCTP:
            pkt.proto = Proto::SCTP;
            if (caplen >= l4off + 4) {
                pkt.src_port = ntohs(*reinterpret_cast<const uint16_t*>(data + l4off));
                pkt.dst_port = ntohs(*reinterpret_cast<const uint16_t*>(data + l4off + 2));
            }
            break;
        case IPPROTO_OSPFIGP:
            pkt.proto = Proto::OSPF;
            break;
        default:
            pkt.proto = Proto::OTHER;
            break;
    }

    if (l7len > 0) {
        const uint8_t* l7 = data + l7off;
        if      (pkt.is_dns())   parse_dns(l7, l7len, pkt);
        else if (pkt.is_http())  parse_http(l7, l7len, pkt);
        else if (pkt.is_https()) {
            if (pkt.proto == Proto::TCP) parse_tls_sni(l7, l7len, pkt);
            else                         parse_quic_sni(l7, l7len, pkt);
        }
    }
    return true;
}

bool parse_packet(const uint8_t* data, uint32_t caplen, Packet& pkt)
{
    if (caplen < sizeof(ethhdr)) return false;
    const auto* eth = reinterpret_cast<const ethhdr*>(data);
    uint16_t etype  = ntohs(eth->h_proto);
    uint32_t l3off  = sizeof(ethhdr);

    if (etype == 0x8100) {
        if (caplen < l3off + 4) return false;
        etype  = ntohs(*reinterpret_cast<const uint16_t*>(data + l3off + 2));
        l3off += 4;
    }

    if (etype == ETH_P_ARP) {
        if (caplen < l3off + 28) return false;
        pkt.proto  = Proto::ARP;
        pkt.length = caplen;
        parse_arp(data + l3off, caplen - l3off, pkt);
        return true;
    }

    if (etype == ETH_P_IPV6) {
        if (caplen < l3off + 40) return false;
        const uint8_t* ip6 = data + l3off;
        uint16_t payload_len = (uint16_t(ip6[4]) << 8) | ip6[5];
        uint8_t  next_header = ip6[6];

        pkt.is_ipv6 = true;
        pkt.src_ip  = ip6_str(ip6 + 8);
        pkt.dst_ip  = ip6_str(ip6 + 24);
        pkt.length  = uint32_t(payload_len) + 40;

        uint32_t l4off = l3off + 40;
        return parse_l4(next_header, data, caplen, l4off, pkt);
    }

    if (etype != ETH_P_IP) return false;

    if (caplen < l3off + sizeof(iphdr)) return false;
    const auto* iph = reinterpret_cast<const iphdr*>(data + l3off);
    if (iph->version != 4) return false;

    pkt.src_ip = ip4_str(iph->saddr);
    pkt.dst_ip = ip4_str(iph->daddr);
    pkt.length = ntohs(iph->tot_len);

    uint32_t l4off = l3off + iph->ihl * 4u;
    return parse_l4(iph->protocol, data, caplen, l4off, pkt);
}
