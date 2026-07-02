#pragma once
#include "packet.hpp"
#include <string>
#include <fstream>
#include <mutex>
#include <atomic>

class CsvLogger {
public:
    CsvLogger(const std::string& path, int limit);

    void log(const Packet& pkt);
    bool finished() const;
    const std::string& path() const { return path_; }
    int  written()  const { return written_.load(std::memory_order_relaxed); }

private:
    std::string       path_;
    std::ofstream     file_;
    std::mutex        mtx_;
    int               limit_;
    std::atomic<int>  written_{ 0 };
};

std::string default_csv_path();
