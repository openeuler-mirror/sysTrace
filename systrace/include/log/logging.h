#pragma once

#ifdef __cplusplus
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <string>
#include <type_traits>
#endif

enum LogLevel { DEBUG = 0, WARN = 1, INFO = 2, ERROR = 3, FATAL = 4 };

#ifdef __cplusplus
namespace systrace {
namespace log {

extern LogLevel g_min_log_level;

class LogStream {
  public:
    LogStream(std::ostream &console_stream);
    bool setLogFile(const std::string &base_dir);
    void closeLogFile();
    bool isFileEnabled() const { return file_enabled_; }

    const std::string &getRankStr() const { return rank_str_; }

    template <typename T> LogStream &operator<<(const T &value) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (log_file_.fail())
            log_file_.clear();

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
        if (file_enabled_ && log_file_.is_open())
            log_file_.flush();
    }

  private:
    std::ostream &console_;
    std::ofstream log_file_;
    bool file_enabled_;
    std::string rank_str_;
    mutable std::mutex mutex_;
};

extern LogStream *g_main_log_stream;
LogStream &getLogStream();
const char *getLogLevelTag(LogLevel level);

class LogLine {
  public:
    LogLine(LogStream &stream, LogLevel level, const char *module = nullptr)
        : stream_(stream), level_(level), module_(module), first_output_(true) {
        enabled_ = (level_ >= g_min_log_level);
    }

    ~LogLine() {
        if (enabled_) {
            stream_ << std::endl;
            stream_.flush();
        }
    }

    template <typename T> LogLine &operator<<(const T &value) {
        if (!enabled_)
            return *this;
        if (first_output_) {
            auto now = std::chrono::system_clock::now();
            auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                          now.time_since_epoch()) %
                      1000;

            std::time_t now_c = std::chrono::system_clock::to_time_t(now);
            std::tm now_tm;
            localtime_r(&now_c, &now_tm);

            stream_ << "[" << std::put_time(&now_tm, "%Y-%m-%d %H:%M:%S") << "."
                    << std::setfill('0') << std::setw(3) << ms.count() << "] ";

            if (module_) {
                stream_ << "[" << module_ << "] ";
            }

            const std::string &rank = stream_.getRankStr();
            if (!rank.empty()) {
                stream_ << "[RANK " << rank << "] ";
            }
            first_output_ = false;
        }
        stream_ << value;
        return *this;
    }

    LogLine &operator<<(std::ostream &(*manip)(std::ostream &)) {
        if (enabled_)
            stream_ << manip;
        return *this;
    }

    bool isEnabled() const { return enabled_; }

  private:
    LogStream &stream_;
    LogLevel level_;
    const char *module_;
    bool first_output_;
    bool enabled_;
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
void systrace_log_warn(const char *module, const char *format, ...);
void systrace_log_error(const char *module, const char *format, ...);
void systrace_log_fatal(const char *module, const char *format, ...);
void systrace_log_debug(const char *module, const char *format, ...);
#ifdef __cplusplus
}
#endif

#define LOG(level)                                                             \
    ::systrace::log::LogLine(::systrace::log::getLogStream(), level)           \
        << "[" << ::systrace::log::getLogLevelTag(level) << "] "

#define LOG_MODULE(level, module)                                              \
    ::systrace::log::LogLine(::systrace::log::getLogStream(), level, module)   \
        << "[" << ::systrace::log::getLogLevelTag(level) << "] "
