#include "cli.hpp"
#include <iostream>
#include <stdexcept>
#include <cstring>
#include <cstdlib>
#include <cctype>

static constexpr const char* VERSION_STR = R"(

      ::::    ::: :::    ::: :::        :::  
     :┼:┼:   :┼: :┼:    :┼: :┼:        :┼:   
    :┼:┼:┼  ┼:┼ ┼:┼    ┼:┼ ┼:┼        ┼:┼    
   ┼#┼ ┼:┼ ┼#┼ ┼#┼    ┼:┼ ┼#┼        ┼#┼     
  ┼#┼  ┼#┼#┼# ┼#┼    ┼#┼ ┼#┼        ┼#┼      
 #┼#   #┼#┼# #┼#    #┼# #┼#        #┼#       
###    ####  ########  ########## ########## 


)";

static constexpr const char* HELP_TEXT = R"(
Usage: null [options]

Capture options:
  -i <iface>         Interface to listen on (default: first active)
  -p <port>          Filter by port number
  --host <ip>        Filter by source or destination IP
  --filter "<expr>"  Raw BPF expression (appended to built-in filter)
  -c <n>             Stop after n packets

Protocol shortcuts:
  --dns              Show only DNS queries
  --http             Show only HTTP traffic
  --https, --tls     Show only HTTPS / TLS traffic
  --icmp             Show only ICMP packets

Display:
  -v, --verbose      Show extra detail (length)
  --no-color         Disable colours (also disables TUI)

Logging:
  --sf [n]           Save captured packets to a CSV file.
                      With a number, saves only the first n packets.
                      Without a number, saves all captured packets.

Utility:
  --list-interfaces  List capture interfaces and exit
  -h, --help         Show this help and exit
  --version          Print version and exit

Examples:
  sudo null -i eth0 --dns
  sudo null -i wlan0 --https -v
  sudo null -p 8080 --http
  sudo null --host 8.8.8.8
  sudo null --filter "tcp port 22" -c 100
  sudo null --sf 500
  sudo null --sf
)";

void print_help(const char*)
{
    std::cout << "  null — network sniffer v2\n" << HELP_TEXT;
}

void print_version()
{
    std::cout << VERSION_STR << '\n';
}

static bool is_number(const char* s)
{
    if (!s || !*s) return false;
    for (const char* p = s; *p; ++p)
        if (!std::isdigit(static_cast<unsigned char>(*p))) return false;
    return true;
}

CliOptions parse_args(int argc, char** argv)
{
    CliOptions opts;
    for (int i = 1; i < argc; ++i) {
        const char* arg = argv[i];
        auto need_next = [&]() -> const char* {
            if (i + 1 >= argc)
                throw std::runtime_error(
                    std::string("'") + arg + "' requires an argument");
            return argv[++i];
        };
        if      (!std::strcmp(arg, "-i"))                opts.interface  = need_next();
        else if (!std::strcmp(arg, "-p")) {
            int p = std::atoi(need_next());
            if (p <= 0 || p > 65535) throw std::runtime_error("Invalid port");
            opts.port = static_cast<uint16_t>(p);
        }
        else if (!std::strcmp(arg, "--host"))            opts.host       = need_next();
        else if (!std::strcmp(arg, "--filter"))          opts.bpf_extra  = need_next();
        else if (!std::strcmp(arg, "-c")) {
            opts.count = std::atoi(need_next());
            if (opts.count < 0) opts.count = 0;
        }
        else if (!std::strcmp(arg, "--dns"))             opts.only_dns   = true;
        else if (!std::strcmp(arg, "--http"))            opts.only_http  = true;
        else if (!std::strcmp(arg, "--https") ||
                 !std::strcmp(arg, "--tls"))             opts.only_https = true;
        else if (!std::strcmp(arg, "--icmp"))            opts.only_icmp  = true;
        else if (!std::strcmp(arg, "-v") ||
                 !std::strcmp(arg, "--verbose"))         opts.verbose    = true;
        else if (!std::strcmp(arg, "--raw"))             opts.show_raw   = true;
        else if (!std::strcmp(arg, "--no-color"))        opts.no_color   = true;
        else if (!std::strcmp(arg, "--list-interfaces")) opts.list_ifaces= true;
        else if (!std::strcmp(arg, "-h") ||
                 !std::strcmp(arg, "--help"))            opts.show_help  = true;
        else if (!std::strcmp(arg, "--version"))         opts.show_version=true;
        else if (!std::strcmp(arg, "--sf")) {
            opts.save_csv = true;
            opts.sf_limit = 0;
            if (i + 1 < argc && is_number(argv[i + 1])) {
                opts.sf_limit = std::atoi(argv[++i]);
            }
        }
        else throw std::runtime_error(std::string("Unknown option: ") + arg);
    }
    return opts;
}
