#include "monitor_server.hpp"
#include "../include/common/shared_constants.h"
#include <sstream>
#include <stdexcept>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <vector>

MonitorServer *MonitorServer::instance_ = nullptr;

MonitorServer &MonitorServer::getInstance()
{
    std::call_once(init_flag_,
                   []()
                   {
                       instance_ = new MonitorServer();
                       instance_->start();
                   });
    return *instance_;
}

MonitorServer::MonitorServer()
{
    if (init_shared_memory() != 0)
    {
        throw std::runtime_error("Failed to initialize shared memory");
    }
}

MonitorServer::~MonitorServer()
{
    stop();
    cleanup_shared_memory();
}

void MonitorServer::start()
{
    if (server_fd_ != -1)
    {
        return;
    }

    server_fd_ = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_fd_ == -1)
    {
        perror("socket");
        throw std::runtime_error("Failed to create socket");
    }
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

    unlink(SOCKET_PATH);

    if (bind(server_fd_, (struct sockaddr *)&addr, sizeof(addr)) == -1)
    {
        perror("bind");
        close(server_fd_);
        server_fd_ = -1;
        throw std::runtime_error("Failed to bind socket");
    }

    if (listen(server_fd_, 5) == -1)
    {
        perror("listen");
        close(server_fd_);
        server_fd_ = -1;
        throw std::runtime_error("Failed to listen on socket");
    }

    server_thread_ = std::thread(&MonitorServer::server_thread_func, this);
}

void MonitorServer::stop()
{
    if (server_fd_ != -1)
    {
        close(server_fd_);
        server_fd_ = -1;
    }

    if (server_thread_.joinable())
    {
        server_thread_.join();
    }

    unlink(SOCKET_PATH);
}

void MonitorServer::server_thread_func()
{
    while (true)
    {
        struct sockaddr_un client_addr;
        socklen_t client_len = sizeof(client_addr);

        int client_fd =
            accept(server_fd_, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd == -1)
        {
            break;
        }

        handle_client(client_fd);
    }
}

void MonitorServer::handle_client(int client_fd)
{
    char buffer[1024];
    ssize_t n = read(client_fd, buffer, sizeof(buffer) - 1);
    if (n <= 0)
    {
        return;
    }
    buffer[n] = '\0';
    std::string command(buffer);

    auto send_response = [client_fd](const std::string &response)
    { write(client_fd, response.c_str(), response.size()); };

    process_command(command, send_response);
}

void MonitorServer::process_command(
    const std::string &cmd,
    const std::function<void(const std::string &)> &send_response)
{
    SharedData *shared_data = get_shared_data();
    if (!shared_data)
    {
        send_response("Error: Shared memory not initialized\n");
        return;
    }

    std::istringstream iss(cmd);
    std::string action;
    iss >> action;

    if (action == "set")
    {
        std::string level_value;
        iss >> level_value;

        size_t eq_pos = level_value.find('=');
        if (eq_pos == std::string::npos)
        {
            send_response("Error: Invalid set command format. Use 'set "
                          "<level>=<true|false>'\n");
            return;
        }

        std::string level = level_value.substr(0, eq_pos);
        std::string value_str = level_value.substr(eq_pos + 1);
        bool value = (value_str == "true");

        pthread_mutex_lock(&shared_data->g_trace_mutex);

        if (level == "L0")
        {
            shared_data->g_dump_L0 = value;
        }
        else if (level == "L1")
        {
            shared_data->g_dump_L1 = value;
        }
        else if (level == "L2")
        {
            shared_data->g_dump_L2 = value;
        }
        else if (level == "L3")
        {
            shared_data->g_dump_L3 = value;
        }
        else
        {
            pthread_mutex_unlock(&shared_data->g_trace_mutex);
            send_response("Error: Unknown level '" + level + "'\n");
            return;
        }

        pthread_mutex_unlock(&shared_data->g_trace_mutex);
        send_response("OK\n");
    }
    else if (action == "interval")
    {
        std::string level_value;
        iss >> level_value;

        size_t eq_pos = level_value.find('=');
        if (eq_pos == std::string::npos)
        {
            send_response("Error: Invalid interval command format. Use "
                          "'interval <level>=<value>'\n");
            return;
        }

        std::string level = level_value.substr(0, eq_pos);
        float value;
        try
        {
            value = std::stof(level_value.substr(eq_pos + 1));
        }
        catch (...)
        {
            send_response("Error: Invalid interval value\n");
            return;
        }

        pthread_mutex_lock(&shared_data->g_trace_mutex);

        if (level == "L1")
        {
            shared_data->g_dump_L1_interval = value;
        }
        else if (level == "L2")
        {
            shared_data->g_dump_L2_interval = value;
        }
        else if (level == "L3")
        {
            shared_data->g_dump_L3_interval = value;
        }
        else
        {
            pthread_mutex_unlock(&shared_data->g_trace_mutex);
            send_response("Error: Unknown level '" + level + "'\n");
            return;
        }

        pthread_mutex_unlock(&shared_data->g_trace_mutex);
        send_response("OK\n");
    }
    else if (action == "print")
    {
        std::string level;
        iss >> level;

        std::ostringstream oss;

        pthread_mutex_lock(&shared_data->g_trace_mutex);

        if (level.empty() || level == "all")
        {
            oss << "Current settings:\n"
                << "  L0: " << (shared_data->g_dump_L0 ? "true" : "false")
                << "\n"
                << "  L1: " << (shared_data->g_dump_L1 ? "true" : "false")
                << "\n"
                << "  L2: " << (shared_data->g_dump_L2 ? "true" : "false")
                << "\n"
                << "  L3: " << (shared_data->g_dump_L3 ? "true" : "false")
                << "\n"
                << "  L1_interval: " << shared_data->g_dump_L1_interval << "\n"
                << "  L2_interval: " << shared_data->g_dump_L2_interval << "\n"
                << "  L3_interval: " << shared_data->g_dump_L3_interval << "\n";
        }
        else if (level == "L0")
        {
            oss << "L0: " << (shared_data->g_dump_L0 ? "true" : "false")
                << "\n";
        }
        else if (level == "L1")
        {
            oss << "L1: " << (shared_data->g_dump_L1 ? "true" : "false") << "\n"
                << "L1_interval: " << shared_data->g_dump_L1_interval << "\n";
        }
        else if (level == "L2")
        {
            oss << "L2: " << (shared_data->g_dump_L2 ? "true" : "false") << "\n"
                << "L2_interval: " << shared_data->g_dump_L2_interval << "\n";
        }
        else if (level == "L3")
        {
            oss << "L3: " << (shared_data->g_dump_L3 ? "true" : "false") << "\n"
                << "L3_interval: " << shared_data->g_dump_L3_interval << "\n";
        }
        else
        {
            pthread_mutex_unlock(&shared_data->g_trace_mutex);
            send_response("Error: Unknown level '" + level + "'\n");
            return;
        }

        pthread_mutex_unlock(&shared_data->g_trace_mutex);
        send_response(oss.str());
    }
    else
    {
        send_response("Error: Unknown command '" + action + "'\n");
    }
}