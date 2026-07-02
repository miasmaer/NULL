#pragma once
#include <string>
#include <cstdint>

struct CliOptions {
    std::string interface;
    std::string bpf_extra;
    bool     only_dns    = false;
    bool     only_http   = false;
    bool     only_https  = false;
    bool     only_icmp   = false;
    uint16_t port        = 0;
    std::string host;
    bool     verbose     = false;
    bool     show_raw    = false;
    bool     no_color    = false;
    int      count       = 0;
    bool     list_ifaces = false;
    bool     show_help   = false;
    bool     show_version= false;
    bool     save_csv    = false;
    int      sf_limit    = 0;
};

CliOptions parse_args(int argc, char** argv);
void       print_help(const char* argv0);
void       print_version();
