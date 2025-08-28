#ifndef SYS_TRACE_SERVER_HPP
#define SYS_TRACE_SERVER_HPP

#include "../include/common/shared_constants.h"
#include <functional>
#include <mutex>
#include <atomic>
#include <thread>

class MonitorServer
{
  public:
    static MonitorServer &getInstance();

    void start();
    void stop();
    static void cleanup()
    {
        if (instance_)
        {
            instance_->stop();
            cleanup_shared_memory();
        }
    }

    MonitorServer(const MonitorServer &) = delete;
    MonitorServer &operator=(const MonitorServer &) = delete;

  private:
    MonitorServer();
    ~MonitorServer();

    void server_thread_func();
    void handle_client(int client_fd);
    void process_command(
        const std::string &cmd,
        const std::function<void(const std::string &)> &send_response);

    static constexpr const char *SOCKET_PATH = "/tmp/sysTrace_socket";

    int server_fd_{-1};
    std::thread server_thread_;
    std::atomic<bool> should_run_{true};

    static MonitorServer *instance_;
    inline static std::once_flag init_flag_;
};

#endif // SYS_TRACE_SERVER_HPP