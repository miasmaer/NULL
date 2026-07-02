#include "tui.hpp"
#include <ncurses.h>
#include <ctime>
#include <cstring>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <thread>

enum {
    CP_NORM   = 0,
    CP_HEADER = 1,
    CP_DNS    = 2,
    CP_HTTP   = 3,
    CP_TLS    = 4,
    CP_UDP    = 5,
    CP_ICMP   = 6,
    CP_TCP    = 7,
    CP_DIM    = 8,
    CP_STAT   = 9,
    CP_SEL    = 10,
    CP_BORDER = 11,
    CP_ALERT  = 12,
    CP_ACCENT = 13,
    CP_BADGE_DNS  = 14,
    CP_BADGE_HTTP = 15,
    CP_BADGE_TLS  = 16,
    CP_BADGE_UDP  = 17,
    CP_BADGE_ICMP = 18,
    CP_BADGE_TCP  = 19,
    CP_ARP        = 20,
    CP_BADGE_ARP  = 21,
    CP_OTHER      = 22,
    CP_BADGE_OTHER= 23,
};

static void init_colors()
{
    start_color();
    use_default_colors();

    init_pair(CP_HEADER, COLOR_WHITE,   COLOR_BLUE);
    init_pair(CP_DNS,    COLOR_CYAN,    -1);
    init_pair(CP_HTTP,   COLOR_YELLOW,  -1);
    init_pair(CP_TLS,    COLOR_GREEN,   -1);
    init_pair(CP_UDP,    COLOR_BLUE,    -1);
    init_pair(CP_ICMP,   COLOR_MAGENTA, -1);
    init_pair(CP_TCP,    COLOR_WHITE,   -1);
    init_pair(CP_DIM,    8,             -1);
    init_pair(CP_STAT,   COLOR_CYAN,    -1);
    init_pair(CP_SEL,    COLOR_BLACK,   COLOR_CYAN);
    init_pair(CP_BORDER, COLOR_BLUE,    -1);
    init_pair(CP_ALERT,  COLOR_RED,     -1);
    init_pair(CP_ACCENT, COLOR_WHITE,   -1);
    init_pair(CP_ARP,    COLOR_RED,     -1);
    init_pair(CP_OTHER,  COLOR_WHITE,   -1);

    init_pair(CP_BADGE_DNS,  COLOR_BLACK, COLOR_CYAN);
    init_pair(CP_BADGE_HTTP, COLOR_BLACK, COLOR_YELLOW);
    init_pair(CP_BADGE_TLS,  COLOR_BLACK, COLOR_GREEN);
    init_pair(CP_BADGE_UDP,  COLOR_BLACK, COLOR_BLUE);
    init_pair(CP_BADGE_ICMP, COLOR_BLACK, COLOR_MAGENTA);
    init_pair(CP_BADGE_TCP,  COLOR_WHITE, 8);
    init_pair(CP_BADGE_ARP,  COLOR_WHITE, COLOR_RED);
    init_pair(CP_BADGE_OTHER,COLOR_BLACK, COLOR_WHITE);
}

static int proto_cp(const std::string& p)
{
    if (p == "DNS")    return CP_DNS;
    if (p == "HTTP")   return CP_HTTP;
    if (p == "TLS")    return CP_TLS;
    if (p == "UDP")    return CP_UDP;
    if (p == "ICMP")   return CP_ICMP;
    if (p == "TCP")    return CP_TCP;
    if (p == "ARP")    return CP_ARP;
    return CP_OTHER;
}

static int proto_badge_cp(const std::string& p)
{
    if (p == "DNS")    return CP_BADGE_DNS;
    if (p == "HTTP")   return CP_BADGE_HTTP;
    if (p == "TLS")    return CP_BADGE_TLS;
    if (p == "UDP")    return CP_BADGE_UDP;
    if (p == "ICMP")   return CP_BADGE_ICMP;
    if (p == "TCP")    return CP_BADGE_TCP;
    if (p == "ARP")    return CP_BADGE_ARP;
    return CP_BADGE_OTHER;
}

static std::string trunc(const std::string& s, int width)
{
    if (width <= 0) return "";
    if ((int)s.size() <= width) return s;
    return s.substr(0, std::max(0, width - 1)) + "~";
}

static std::string fmt_bytes(uint64_t b)
{
    if (b < 1024)      return std::to_string(b) + " B";
    if (b < 1048576)   return std::to_string(b / 1024) + " KB";
    return std::to_string(b / 1048576) + " MB";
}

static std::string fmt_time(std::time_t t)
{
    char buf[16];
    struct tm* tm = std::localtime(&t);
    std::strftime(buf, sizeof(buf), "%H:%M:%S", tm);
    return buf;
}

Tui::Tui(const CliOptions& opts, const std::string& iface,
         const std::string& filter)
    : opts_(opts), iface_(iface), filter_(filter)
{
    initscr();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    nodelay(stdscr, TRUE);
    curs_set(0);
    init_colors();
}

Tui::~Tui()
{
    endwin();
}

void Tui::push(const Packet& pkt)
{
    DisplayRow row;
    if      (pkt.is_dns())             row.proto = "DNS";
    else if (pkt.is_https())           row.proto = "TLS";
    else if (pkt.is_http())            row.proto = "HTTP";
    else if (pkt.proto == Proto::UDP)  row.proto = "UDP";
    else if (pkt.proto == Proto::ICMP) row.proto = "ICMP";
    else if (pkt.proto == Proto::TCP)  row.proto = "TCP";
    else if (pkt.proto == Proto::ARP)  row.proto = "ARP";
    else                                row.proto = pkt.proto_str();

    row.src  = pkt.src_ip + ":" + std::to_string(pkt.src_port);
    row.dst  = pkt.dst_ip + ":" + std::to_string(pkt.dst_port);
    if (!pkt.hostname.empty()) {
        row.info = pkt.hostname;
    } else if (!pkt.http_method.empty()) {
        row.info = pkt.http_method + " " + pkt.http_path;
    } else {
        row.info = "len=" + std::to_string(pkt.length);
    }

    row.service = pkt.service();
    row.length  = pkt.length;
    row.ts      = std::time(nullptr);

    total_.fetch_add(1, std::memory_order_relaxed);
    bytes_.fetch_add(pkt.length, std::memory_order_relaxed);
    if      (row.proto == "DNS")  dns_cnt_.fetch_add(1,   std::memory_order_relaxed);
    else if (row.proto == "HTTP") http_cnt_.fetch_add(1,  std::memory_order_relaxed);
    else if (row.proto == "TLS")  tls_cnt_.fetch_add(1,   std::memory_order_relaxed);
    else if (row.proto == "UDP")  udp_cnt_.fetch_add(1,   std::memory_order_relaxed);
    else if (row.proto == "ICMP") icmp_cnt_.fetch_add(1,  std::memory_order_relaxed);
    else if (row.proto == "TCP")  tcp_cnt_.fetch_add(1,   std::memory_order_relaxed);
    else if (row.proto == "ARP")  arp_cnt_.fetch_add(1,   std::memory_order_relaxed);
    else                          other_cnt_.fetch_add(1, std::memory_order_relaxed);

    std::lock_guard<std::mutex> lock(rows_mtx_);
    rows_.push_back(std::move(row));
    if ((int)rows_.size() > MAX_HISTORY) rows_.pop_front();
}

bool Tui::done() const { return done_.load(std::memory_order_acquire); }
void Tui::set_done()   { done_.store(true, std::memory_order_release); }

int Tui::run(int limit)
{
    using clock = std::chrono::steady_clock;
    auto next_draw = clock::now();

    while (!done_.load(std::memory_order_acquire)) {
        int ch = getch();
        handle_key(ch);

        if (limit > 0 && total_.load() >= limit)
            done_.store(true, std::memory_order_release);

        auto now = clock::now();
        if (now >= next_draw) {
            draw();
            next_draw = now + std::chrono::milliseconds(80);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    return total_.load();
}

void Tui::handle_key(int ch)
{
    int rows, cols;
    getmaxyx(stdscr, rows, cols);
    (void)rows; (void)cols;

    switch (ch) {
        case 'q': case 'Q': case 27:
            done_.store(true, std::memory_order_release);
            break;
        case KEY_DOWN: case 'j':
            scroll_++;
            break;
        case KEY_UP: case 'k':
            if (scroll_ > 0) scroll_--;
            break;
        case KEY_NPAGE:
            scroll_ += std::max(1, max_rows_ - 1);
            break;
        case KEY_PPAGE:
            scroll_ = std::max(0, scroll_ - std::max(1, max_rows_ - 1));
            break;
        case 'g': case KEY_HOME:
            scroll_ = 0;
            break;
        case 'G': case KEY_END: {
            std::lock_guard<std::mutex> lock(rows_mtx_);
            int n = (int)rows_.size();
            scroll_ = std::max(0, n - max_rows_);
            break;
        }
        default: break;
    }
}

void Tui::draw()
{
    erase();
    draw_header();
    draw_table();
    draw_footer();
    refresh();
}

void Tui::draw_header()
{
    int rows, cols;
    getmaxyx(stdscr, rows, cols);
    (void)rows;

    attron(COLOR_PAIR(CP_HEADER) | A_BOLD);
    for (int x = 0; x < cols; x++) mvaddch(0, x, ' ');
    mvaddstr(0, 2, "NULL");
    attroff(A_BOLD);

    std::string centre = "iface: " + iface_;
    if (!filter_.empty()) centre += "  filter: " + filter_;
    int cx = std::max(0, (cols - (int)centre.size()) / 2);
    mvaddstr(0, cx, centre.c_str());

    char timebuf[16];
    time_t now = std::time(nullptr);
    strftime(timebuf, sizeof(timebuf), "%H:%M:%S", std::localtime(&now));
    std::string ts(timebuf);
    mvaddstr(0, cols - (int)ts.size() - 2, ts.c_str());
    attroff(COLOR_PAIR(CP_HEADER));

    int x = 1;
    auto pill = [&](const char* label, int cnt, int badge_cp, int fg_cp) {
        if (x + 14 > cols) return;
        attron(COLOR_PAIR(badge_cp) | A_BOLD);
        mvaddstr(1, x, label);
        attroff(A_BOLD);
        attroff(COLOR_PAIR(badge_cp));
        attron(COLOR_PAIR(fg_cp));
        std::string n = " " + std::to_string(cnt) + " ";
        mvaddstr(1, x + (int)strlen(label), n.c_str());
        attroff(COLOR_PAIR(fg_cp));
        x += (int)strlen(label) + (int)n.size() + 1;
    };

    mvaddch(1, 0, ' ');
    pill(" DNS",  dns_cnt_.load(),   CP_BADGE_DNS,   CP_DNS);
    pill(" HTTP", http_cnt_.load(),  CP_BADGE_HTTP,  CP_HTTP);
    pill(" TLS",  tls_cnt_.load(),   CP_BADGE_TLS,   CP_TLS);
    pill(" UDP",  udp_cnt_.load(),   CP_BADGE_UDP,   CP_UDP);
    pill(" ICMP", icmp_cnt_.load(),  CP_BADGE_ICMP,  CP_ICMP);
    pill(" TCP",  tcp_cnt_.load(),   CP_BADGE_TCP,   CP_TCP);
    pill(" ARP",  arp_cnt_.load(),   CP_BADGE_ARP,   CP_ARP);
    pill(" OTH",  other_cnt_.load(), CP_BADGE_OTHER, CP_OTHER);

    std::string tot = std::to_string(total_.load()) + " pkts";
    std::string byt = fmt_bytes(bytes_.load());
    std::string right = tot + "  " + byt;
    int rx = cols - (int)right.size() - 2;
    if (rx > x) {
        attron(COLOR_PAIR(CP_DIM));
        mvaddstr(1, rx, right.c_str());
        attroff(COLOR_PAIR(CP_DIM));
    }

    attron(COLOR_PAIR(CP_BORDER));
    for (int c = 0; c < cols; c++) mvaddch(2, c, ACS_HLINE);
    attroff(COLOR_PAIR(CP_BORDER));

    attron(A_BOLD | COLOR_PAIR(CP_DIM));
    mvaddstr(3, 1,  "TIME    ");
    mvaddstr(3, 9,  "PROTOCOL  ");
    mvaddstr(3, 17, "SOURCE                ");
    mvaddstr(3, 40, "DESTINATION           ");
    mvaddstr(3, 63, "SVC      ");
    mvaddstr(3, 73, "INFO");
    attroff(A_BOLD | COLOR_PAIR(CP_DIM));

    attron(COLOR_PAIR(CP_BORDER));
    for (int c = 0; c < cols; c++) mvaddch(4, c, ACS_HLINE);
    attroff(COLOR_PAIR(CP_BORDER));
}

void Tui::draw_table()
{
    int rows, cols;
    getmaxyx(stdscr, rows, cols);

    const int TABLE_TOP    = 5;
    const int TABLE_BOTTOM = rows - 2;
    max_rows_ = std::max(1, TABLE_BOTTOM - TABLE_TOP);

    std::lock_guard<std::mutex> lock(rows_mtx_);
    int total = (int)rows_.size();

    if (scroll_ > std::max(0, total - max_rows_))
        scroll_ = std::max(0, total - max_rows_);

    int screen_row = TABLE_TOP;
    for (int i = scroll_; i < total && screen_row < TABLE_BOTTOM; ++i, ++screen_row) {
        const DisplayRow& r = rows_[i];
        bool alt = (i % 2 == 0);

        if (alt) attron(A_DIM);

        attron(COLOR_PAIR(CP_DIM));
        mvaddstr(screen_row, 1, fmt_time(r.ts).c_str());
        attroff(COLOR_PAIR(CP_DIM));

        int bcp = proto_badge_cp(r.proto);
        attron(COLOR_PAIR(bcp) | A_BOLD);
        std::string badge = " " + r.proto + " ";
        mvaddstr(screen_row, 9, badge.c_str());
        attroff(COLOR_PAIR(bcp) | A_BOLD);

        int fcp = proto_cp(r.proto);
        attron(COLOR_PAIR(fcp));
        mvaddstr(screen_row, 17, trunc(r.src, 22).c_str());
        attroff(COLOR_PAIR(fcp));

        attron(COLOR_PAIR(CP_ACCENT));
        mvaddstr(screen_row, 40, trunc(r.dst, 22).c_str());
        attroff(COLOR_PAIR(CP_ACCENT));

        attron(COLOR_PAIR(CP_DIM));
        mvaddstr(screen_row, 63, trunc(r.service, 8).c_str());
        attroff(COLOR_PAIR(CP_DIM));

        if (!r.info.empty()) {
            attron(COLOR_PAIR(fcp) | A_BOLD);
            int info_width = cols - 73 - 1;
            mvaddstr(screen_row, 73, trunc(r.info, info_width).c_str());
            attroff(COLOR_PAIR(fcp) | A_BOLD);
        }

        if (alt) attroff(A_DIM);
    }

    if (total == 0) {
        attron(COLOR_PAIR(CP_DIM));
        const char* msg = "LISTENING...";
        int msglen = (int)strlen(msg);
        mvaddstr(TABLE_TOP + max_rows_ / 2, std::max(0, (cols - msglen) / 2), msg);
        attroff(COLOR_PAIR(CP_DIM));
    }
}

void Tui::draw_footer()
{
    int rows, cols;
    getmaxyx(stdscr, rows, cols);

    attron(COLOR_PAIR(CP_BORDER));
    for (int c = 0; c < cols; c++) mvaddch(rows - 2, c, ACS_HLINE);
    attroff(COLOR_PAIR(CP_BORDER));

    attron(COLOR_PAIR(CP_DIM));
    mvaddstr(rows - 1, 1, "q => quit, pgDn/pgUp for scroll(mouse scroll works)");
    attroff(COLOR_PAIR(CP_DIM));

    int total;
    {
        std::lock_guard<std::mutex> lock(rows_mtx_);
        total = (int)rows_.size();
    }

    if (total > 0) {
        std::string ind = std::to_string(std::min(scroll_ + max_rows_, total))
                        + "/" + std::to_string(total);
        attron(COLOR_PAIR(CP_STAT) | A_BOLD);
        mvaddstr(rows - 1, cols - (int)ind.size() - 2, ind.c_str());
        attroff(COLOR_PAIR(CP_STAT) | A_BOLD);
    }
}
