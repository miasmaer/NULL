#include "cli.hpp"
#include "sniffer.hpp"
#include "packet.hpp"
#include "tui.hpp"
#include "csv_logger.hpp"

#include <iostream>
#include <memory>
#include <thread>
#include <stdexcept>
#include <csignal>

static Sniffer* g_sniffer = nullptr;
static Tui*     g_tui     = nullptr;

static void on_signal(int)
{
    if (g_tui)     g_tui->set_done();
    if (g_sniffer) g_sniffer->stop();
}

static std::string build_bpf(const CliOptions& opts)
{
    std::vector<std::string> parts;
    if (opts.port)            parts.push_back("port " + std::to_string(opts.port));
    if (!opts.host.empty())   parts.push_back("host " + opts.host);
    std::vector<std::string> proto_filters;
    if (opts.only_dns)        proto_filters.push_back("port 53");
    if (opts.only_http)       proto_filters.push_back("tcp port 80");
    if (opts.only_https)      proto_filters.push_back("tcp port 443");
    if (opts.only_icmp)       proto_filters.push_back("icmp or icmp6");

    if (!proto_filters.empty()) {
        std::string proto_part = proto_filters[0];
        for (size_t i = 1; i < proto_filters.size(); ++i) {
            proto_part += " or " + proto_filters[i];
        }
        parts.push_back("(" + proto_part + ")");
    }

    if (!opts.bpf_extra.empty()) parts.push_back("(" + opts.bpf_extra + ")");
    if (parts.empty()) return "";
    std::string r = parts[0];
    for (size_t i = 1; i < parts.size(); ++i) r += " and " + parts[i];
    return r;
}

static void print_packet_plain(const Packet& pkt)
{
    std::string proto;
    if      (pkt.is_dns())             proto = "DNS";
    else if (pkt.is_https())           proto = "TLS";
    else if (pkt.is_http())            proto = "HTTP";
    else if (pkt.proto == Proto::UDP)  proto = "UDP";
    else if (pkt.proto == Proto::ICMP) proto = "ICMP";
    else if (pkt.proto == Proto::TCP)  proto = "TCP";
    else if (pkt.proto == Proto::ARP)  proto = "ARP";
    else                                proto = pkt.proto_str();

    std::cout << '[' << proto << "] "
              << pkt.src_ip << ':' << pkt.src_port
              << " -> "
              << pkt.dst_ip << ':' << pkt.dst_port;

    if (!pkt.hostname.empty())    std::cout << "  " << pkt.hostname;
    if (!pkt.http_method.empty()) std::cout << "  " << pkt.http_method << " " << pkt.http_path;
    std::cout << "  len=" << pkt.length;
    std::cout << '\n';
}

int main(int argc, char** argv)
{
    CliOptions opts;
    try {
        opts = parse_args(argc, argv);
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << '\n';
        print_help(argv[0]);
        return 1;
    }

    if (opts.show_help)    { print_help(argv[0]); return 0; }
    if (opts.show_version) { print_version();      return 0; }

    if (opts.list_ifaces) {
        try {
            for (const auto& iface : list_interfaces())
                std::cout << iface << '\n';
        } catch (const std::exception& e) {
            std::cerr << "Error: " << e.what() << '\n';
            return 1;
        }
        return 0;
    }

    CaptureOptions cap;
    cap.interface  = opts.interface;
    cap.bpf_filter = build_bpf(opts);
    cap.promisc    = true;
    cap.snaplen    = SNAPLEN;
    cap.timeout_ms = 1;

    std::unique_ptr<Sniffer> sniffer;
    try {
        sniffer = std::make_unique<Sniffer>(cap);
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << '\n';
        std::cerr << "Make sure that you are root.\n";
        return 1;
    }

    g_sniffer = sniffer.get();
    std::signal(SIGINT,  on_signal);
    std::signal(SIGTERM, on_signal);

    std::unique_ptr<CsvLogger> logger;
    if (opts.save_csv) {
        try {
            logger = std::make_unique<CsvLogger>(default_csv_path(), opts.sf_limit);
            std::cerr << "logging to " << logger->path()
                      << (opts.sf_limit > 0 ? (" (first " + std::to_string(opts.sf_limit) + " packets)") : " (all packets)")
                      << '\n';
        } catch (const std::exception& e) {
            std::cerr << "Error: " << e.what() << '\n';
            return 1;
        }
    }

    if (opts.no_color) {
        int captured = 0;
        int limit    = opts.count;
        std::cout << "NULL | " << sniffer->active_interface();
        if (!cap.bpf_filter.empty()) std::cout << " | " << cap.bpf_filter;
        std::cout << '\n';
        try {
            sniffer->start([&](const Packet& pkt) {
                if (opts.only_dns   && !pkt.is_dns())   return;
                if (opts.only_http  && !pkt.is_http())  return;
                if (opts.only_https && !pkt.is_https()) return;
                print_packet_plain(pkt);
                if (logger) logger->log(pkt);
                if (limit > 0 && ++captured >= limit) sniffer->stop();
            });
        } catch (const std::exception& e) {
            std::cerr << "Capture error: " << e.what() << '\n';
            return 1;
        }
        std::cout << "\ncaptured " << captured << " packet(s)\n";
        if (logger) std::cerr << "wrote " << logger->written() << " row(s) to " << logger->path() << '\n';
        return 0;
    }

    auto tui = std::make_unique<Tui>(opts, sniffer->active_interface(),
                                     cap.bpf_filter);
    g_tui = tui.get();

    std::thread capture_thread([&] {
        try {
            sniffer->start([&](const Packet& pkt) {
                if (opts.only_dns   && !pkt.is_dns())   return;
                if (opts.only_http  && !pkt.is_http())  return;
                if (opts.only_https && !pkt.is_https()) return;

                tui->push(pkt);
                if (logger) logger->log(pkt);

                if (tui->done()) sniffer->stop();
            });
        } catch (...) {
            sniffer->stop();
        }
    });

    int total = tui->run(opts.count);
    sniffer->stop();
    capture_thread.join();

    std::cout << "\nnull — captured " << total << " packet(s)\n";
    if (logger) std::cout << "wrote " << logger->written() << " row(s) to " << logger->path() << '\n';
    return 0;
}
