#pragma once

#ifdef __cplusplus
#include <fstream>
#include <iostream>
#include <mutex>
#include <string>
#include <cstring>
#include <type_traits>
#include <cstdlib>
#endif

enum LogLevel { INFO, WARNING, ERROR, FATAL };

#ifdef __cplusplus
namespace systrace {
namespace log {

class LogStream {
public:
    LogStream(std::ostream &console_stream);
    bool setLogFile(const std::string &file_path);
    void closeLogFile();
    bool isFileEnabled() const { return file_enabled_; }
    
    const std::string& getRankStr() const { return rank_str_; }

    template <typename T>
    LogStream &operator<<(const T &value) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (log_file_.fail()) log_file_.clear();

        if (!file_enabled_) {
            console_ << value;
        }

        if (file_enabled_ && log_file_.is_open()) {
            log_file_ << value;
        }
        return *this;
    }

    LogStream &operator<<(std::ostream &(*manip)(std::ostream &)) {
        std::lock_guard<std::mutex> lock(mutex_);
        
        if (!file_enabled_) {
            manip(console_);
        }

        if (file_enabled_ && log_file_.is_open()) {
            manip(log_file_);
        }
        return *this;
    }

    void flush() {
        std::lock_guard<std::mutex> lock(mutex_);
        console_.flush();
        if (file_enabled_ && log_file_.is_open()) log_file_.flush();
    }

private:
    std::ostream &console_;
    std::ofstream log_file_;
    bool file_enabled_;
    std::string rank_str_; 
    mutable std::mutex mutex_;
};

extern LogStream* g_main_log_stream;
LogStream &getLogStream();
const char *getLogLevelTag(LogLevel level);

class LogLine {
public:
    LogLine(LogStream &stream, const char *module = nullptr) 
        : stream_(stream), module_(module), first_output_(true) {}
    
    ~LogLine() { stream_ << std::endl; stream_.flush(); }
    
    template <typename T>
    LogLine &operator<<(const T &value) {
        if (first_output_) {
            if (module_) {
                stream_ << "[" << module_ << "] ";
            }
            const std::string& rank = stream_.getRankStr();
            if (!rank.empty()) {
                stream_ << "[RANK " << rank << "] ";
            }
            first_output_ = false;
        }
        stream_ << value;
        return *this;
    }

    LogLine &operator<<(std::ostream &(*manip)(std::ostream &)) {
        stream_ << manip; return *this;
    }

private:
    LogStream &stream_;
    const char *module_;
    bool first_output_;
};
} // namespace log

void setLoggingPath(const std::string &file_path = "");
void closeLoggingFile();
} // namespace systrace
#endif

#ifdef __cplusplus
extern "C" {
#endif
void systrace_log_info(const char *module, const char *format, ...);
void systrace_log_warning(const char *module, const char *format, ...);
void systrace_log_error(const char *module, const char *format, ...);
void systrace_log_fatal(const char *module, const char *format, ...);
#ifdef __cplusplus
}
#endif

#define LOG(level) ::systrace::log::LogLine(::systrace::log::getLogStream()) << ::systrace::log::getLogLevelTag(level)
#define LOG_MODULE(level, module) ::systrace::log::LogLine(::systrace::log::getLogStream(), module) << ::systrace::log::getLogLevelTag(level)