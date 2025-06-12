#include "util.h"
#include "constant.h"
#include <algorithm>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <thread>
#include <unistd.h>

namespace systrace
{
namespace util
{

namespace env
{
std::string_view EnvVarRegistry::DEFAULT_VALUE_STRING = "NONE";
int EnvVarRegistry::DEFAULT_VALUE_INT = 0;
bool EnvVarRegistry::DEFAULT_VALUE_BOOL = false;
} // namespace env
namespace fs_utils
{

int CreateDirectoryIfNotExists(const std::string &path)
{
    std::filesystem::path d_path(path);
    try
    {
        if (!std::filesystem::exists(d_path))
        {
            std::filesystem::create_directories(d_path);
        }
        if (!std::filesystem::is_directory(d_path))
        {
            LOG(ERROR) << "Path exists but is not a directory: " << path;
            return 1;
        }
    }
    catch (const std::filesystem::filesystem_error &e)
    {
        LOG(ERROR) << "Failed to create directory " << path << ": " << e.what();
        return 1;
    }
    return 0;
}

std::string GenerateClusterUniqueFilename(const std::string &suffix)
{
    try
    {
        char hostname[128];
        gethostname(hostname, sizeof(hostname));
        std::ostringstream oss;
        oss << hostname << "--" << std::setw(5) << std::setfill('0')
            << config::GlobalConfig::Instance().rank << suffix;
        return oss.str();
    }
    catch (const std::exception &e)
    {
        LOG(ERROR) << "Filename generation failed: " << e.what();
        return "error_" + std::to_string(std::time(nullptr)) + suffix;
    }
}

} // namespace fs_utils

namespace config
{

class DeviceManager
{
  public:
    static constexpr uint64_t MAX_DEVICES = 16;
    static constexpr const char *DEVICE_PATH_PREFIX = "/dev/davinci";

    static std::vector<uint64_t> DetectAvailableDevices()
    {
        std::vector<uint64_t> available_devices;
        available_devices.reserve(MAX_DEVICES);

        for (uint64_t device_index = 0; device_index < MAX_DEVICES;
             ++device_index)
        {
            if (IsDevicePresent(device_index))
            {
                available_devices.push_back(device_index);
                if (config::GlobalConfig::Instance().local_rank == 0)
                {
                    LOG(INFO)
                        << "Found device: " << GetDevicePath(device_index);
                }
            }
        }

        std::sort(available_devices.begin(), available_devices.end());
        return available_devices;
    }

  private:
    static bool IsDevicePresent(uint64_t index)
    {
        return std::filesystem::exists(GetDevicePath(index));
    }

    static std::string GetDevicePath(uint64_t index)
    {
        return std::string(DEVICE_PATH_PREFIX) + std::to_string(index);
    }
};

namespace
{

GlobalConfig &config = GlobalConfig::Instance();

void LoadEnvironmentVariables()
{
    auto loadInt = [](const char *name)
    { return env::EnvVarRegistry::GetEnvVar<int>(name); };

    auto loadStr = [](const char *name)
    { return env::EnvVarRegistry::GetEnvVar<std::string>(name); };

    config.rank = loadInt("RANK");
    config.job_name = loadStr("ENV_ARGO_WORKFLOW_NAME");
    config.local_rank = loadInt("LOCAL_RANK");
    config.local_world_size = loadInt("LOCAL_WORLD_SIZE");
    config.world_size = loadInt("WORLD_SIZE");
    config.rank_str = "[RANK " + std::to_string(config.rank) + "] ";
}

void ValidateDeviceConfiguration()
{
    config.devices = DeviceManager::DetectAvailableDevices();

    if (config.devices.empty())
    {
        config.enable = false;
        LOG(WARNING) << "No devices found, disabling tracing";
        return;
    }

    if (config.local_world_size != config.devices.size())
    {
        LOG(WARNING) << "Local world size mismatch, disabling hook";
        config.enable = false;
    }
}

} // namespace

void InitializeGlobalConfiguration()
{
    LOG(INFO) << "Initializing global configuration";

    try
    {
        LoadEnvironmentVariables();
        ValidateDeviceConfiguration();
        LOG(INFO) << "Global configuration initialized successfully";
    }
    catch (const std::exception &e)
    {
        LOG(ERROR) << "Global config initialization failed: " << e.what();
        throw;
    }
}

} // namespace config

namespace environment
{

bool IsValidEnvironmentVariableName(const std::string &name)
{
    if (name.empty() || !isalpha(name[0]))
    {
        return false;
    }

    for (char c : name)
    {
        if (!isalnum(c) && c != '_')
        {
            return false;
        }
    }
    return true;
}

void RegisterRequiredEnvironmentVariables()
{
    try
    {
        if (!IsValidEnvironmentVariableName("ENV_ARGO_WORKFLOW_NAME"))
        {
            throw std::invalid_argument(
                "Invalid env var name: ENV_ARGO_WORKFLOW_NAME");
        }
        REGISTER_ENVIRONMENT_VARIABLE(
            "ENV_ARGO_WORKFLOW_NAME",
            env::EnvVarRegistry::DEFAULT_VALUE_STRING);

        if (!IsValidEnvironmentVariableName("SYSTRACE_SYMS_FILE"))
        {
            throw std::invalid_argument(
                "Invalid env var name: SYSTRACE_SYMS_FILE");
        }
        REGISTER_ENVIRONMENT_VARIABLE(
            "SYSTRACE_SYMS_FILE", env::EnvVarRegistry::DEFAULT_VALUE_STRING);

        if (!IsValidEnvironmentVariableName("SYSTRACE_LOGGING_DIR"))
        {
            throw std::invalid_argument(
                "Invalid env var name: SYSTRACE_LOGGING_DIR");
        }
        REGISTER_ENVIRONMENT_VARIABLE(
            "SYSTRACE_LOGGING_DIR", env::EnvVarRegistry::DEFAULT_VALUE_STRING);

        if (!IsValidEnvironmentVariableName("SYSTRACE_HOST_TRACING_FUNC"))
        {
            throw std::invalid_argument(
                "Invalid env var name: SYSTRACE_HOST_TRACING_FUNC");
        }
        REGISTER_ENVIRONMENT_VARIABLE(
            "SYSTRACE_HOST_TRACING_FUNC",
            env::EnvVarRegistry::DEFAULT_VALUE_STRING);

        REGISTER_ENVIRONMENT_VARIABLE("RANK", 0);
        REGISTER_ENVIRONMENT_VARIABLE("LOCAL_RANK", 0);
        REGISTER_ENVIRONMENT_VARIABLE("LOCAL_WORLD_SIZE", 1);
        REGISTER_ENVIRONMENT_VARIABLE("WORLD_SIZE", 1);
        REGISTER_ENVIRONMENT_VARIABLE("SYSTRACE_LOGGING_APPEND", false);
    }
    catch (const std::exception &e)
    {
        LOG(ERROR) << "Environment variable registration failed: " << e.what();
        throw;
    }
}

} // namespace environment

void InitializeSystemUtilities()
{
    environment::RegisterRequiredEnvironmentVariables();
    config::InitializeGlobalConfiguration();
}

std::string GetPrimaryIP()
{
    struct ifaddrs *ifaddr, *ifa;
    std::string primaryIP;

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return "";
    }

    for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr || ifa->ifa_addr->sa_family != AF_INET) {
            continue; 
        }

        if (strcmp(ifa->ifa_name, "lo") == 0) {
            continue;
        }

        struct sockaddr_in *addr = (struct sockaddr_in *)ifa->ifa_addr;
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr->sin_addr, ip, INET_ADDRSTRLEN);

        primaryIP = ip;
        break;
    }

    freeifaddrs(ifaddr);
    return primaryIP;
}

} // namespace util
} // namespace systrace