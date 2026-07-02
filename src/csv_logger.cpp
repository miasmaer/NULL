#include "csv_logger.hpp"
#include <ctime>
#include <stdexcept>

static std::string csv_escape(const std::string& s)
{
    if (s.find_first_of(",\"\n") == std::string::npos) return s;
    std::string out = "\"";
    out.reserve(s.size() + 8);
    for (char c : s) {
        if (c == '"') out += "\"\"";
        else           out += c;
    }
    out += "\"";
    return out;
}

std::string default_csv_path()
{
    std::time_t t = std::time(nullptr);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y%m%d_%H%M%S", std::localtime(&t));
    return std::string("NULL_capture_") + buf + ".csv";
}

CsvLogger::CsvLogger(const std::string& path, int limit)
    : path_(path), limit_(limit)
{
    file_.open(path_, std::ios::out | std::ios::trunc);
    if (!file_.is_open())
        throw std::runtime_error("Failed to open CSV file: " + path_);
    file_ << "time,proto,src_ip,src_port,dst_ip,dst_port,length,service,hostname,http_method,http_path\n";
}

void CsvLogger::log(const Packet& pkt)
{
    if (limit_ > 0 && written_.load(std::memory_order_relaxed) >= limit_) return;

    std::time_t t = std::time(nullptr);
    char tbuf[16];
    std::strftime(tbuf, sizeof(tbuf), "%H:%M:%S", std::localtime(&t));

    std::lock_guard<std::mutex> lock(mtx_);
    if (limit_ > 0 && written_.load(std::memory_order_relaxed) >= limit_) return;

    file_ << tbuf << ','
          << pkt.proto_str() << ','
          << pkt.src_ip << ',' << pkt.src_port << ','
          << pkt.dst_ip << ',' << pkt.dst_port << ','
          << pkt.length << ','
          << csv_escape(pkt.service()) << ','
          << csv_escape(pkt.hostname) << ','
          << csv_escape(pkt.http_method) << ','
          << csv_escape(pkt.http_path) << '\n';

    written_.fetch_add(1, std::memory_order_relaxed);
}

bool CsvLogger::finished() const
{
    return limit_ > 0 && written_.load(std::memory_order_relaxed) >= limit_;
}
