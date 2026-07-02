#include "sniffer.hpp"
#include "packet.hpp"
#include <pcap.h>
#include <stdexcept>
#include <cstring>
#include <vector>
#include <string>

struct DispatchCtx { PacketCallback callback; };

std::vector<std::string> list_interfaces()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* devs = nullptr;
    if (pcap_findalldevs(&devs, errbuf) == PCAP_ERROR || !devs)
        throw std::runtime_error(std::string("pcap_findalldevs: ") + errbuf);
    std::vector<std::string> res;
    for (pcap_if_t* d = devs; d; d = d->next)
        res.emplace_back(d->name);
    pcap_freealldevs(devs);
    return res;
}

Sniffer::Sniffer(const CaptureOptions& opts) : opts_(opts)
{
    char errbuf[PCAP_ERRBUF_SIZE];

    std::string iface = opts_.interface;
    if (iface.empty() || iface == "default") {
        pcap_if_t* devs = nullptr;
        if (pcap_findalldevs(&devs, errbuf) == PCAP_ERROR || !devs)
            throw std::runtime_error(std::string("pcap_findalldevs: ") + errbuf);
        iface = devs->name;
        pcap_freealldevs(devs);
    }
    active_iface_ = iface;

    pcap_t* h = pcap_create(iface.c_str(), errbuf);
    if (!h)
        throw std::runtime_error(std::string("pcap_create: ") + errbuf);
    handle_ = h;

    pcap_set_snaplen(h, opts_.snaplen);
    pcap_set_promisc(h, opts_.promisc ? 1 : 0);
    pcap_set_timeout(h, opts_.timeout_ms > 0 ? opts_.timeout_ms : 1);
    pcap_set_immediate_mode(h, 1);
    pcap_set_buffer_size(h, 8 * 1024 * 1024);

    int activate_rc = pcap_activate(h);
    if (activate_rc < 0) {
        std::string msg = pcap_geterr(h);
        pcap_close(h); handle_ = nullptr;
        throw std::runtime_error("pcap_activate: " + msg);
    }

    if (pcap_datalink(h) != DLT_EN10MB) {
        pcap_close(h); handle_ = nullptr;
        throw std::runtime_error("Only Ethernet (DLT_EN10MB) is supported");
    }

    if (!opts_.bpf_filter.empty()) {
        bpf_program fp{};
        bpf_u_int32 net = 0, mask = 0;
        pcap_lookupnet(iface.c_str(), &net, &mask, errbuf);
        if (pcap_compile(h, &fp, opts_.bpf_filter.c_str(), 1, net) == PCAP_ERROR) {
            pcap_close(h); handle_ = nullptr;
            throw std::runtime_error(std::string("pcap_compile: ") + pcap_geterr(h));
        }
        if (pcap_setfilter(h, &fp) == PCAP_ERROR) {
            pcap_freecode(&fp); pcap_close(h); handle_ = nullptr;
            throw std::runtime_error(std::string("pcap_setfilter: ") + pcap_geterr(h));
        }
        pcap_freecode(&fp);
    }
}

Sniffer::~Sniffer()
{
    if (handle_) pcap_close(static_cast<pcap_t*>(handle_));
}

void Sniffer::dispatch(uint8_t* user,
                       const struct pcap_pkthdr* hdr,
                       const uint8_t* raw)
{
    auto* ctx = reinterpret_cast<DispatchCtx*>(user);
    Packet pkt;
    if (parse_packet(raw, hdr->caplen, pkt))
        ctx->callback(pkt);
}

void Sniffer::start(PacketCallback cb)
{
    running_.store(true);
    DispatchCtx ctx{ std::move(cb) };
    int rc = pcap_loop(static_cast<pcap_t*>(handle_), 0,
                       Sniffer::dispatch,
                       reinterpret_cast<uint8_t*>(&ctx));
    running_.store(false);
    if (rc == PCAP_ERROR)
        throw std::runtime_error(
            std::string("pcap_loop: ") +
            pcap_geterr(static_cast<pcap_t*>(handle_)));
}

void Sniffer::stop()
{
    if (running_.load())
        pcap_breakloop(static_cast<pcap_t*>(handle_));
}
