#pragma once

#include "logging.h"
#include <cstdlib>
#include <deque>
#include <filesystem>
#include <functional>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <variant>
#include <vector>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <cstring>
#include <iostream>

namespace systrace
{
namespace util
{
std::string GetPrimaryIP();
namespace config
{

struct GlobalConfig
{
    uint32_t rank{0};
    uint32_t local_rank{0};
    uint32_t world_size{0};
    uint32_t local_world_size{0};
    pid_t pid{0};
    std::string job_name;
    bool enable{true};
    std::vector<uint64_t> devices;
    std::string rank_str;

    static GlobalConfig &Instance()
    {
        static GlobalConfig instance;
        return instance;
    }

  private:
    GlobalConfig() = default;
};

void InitializeGlobalConfiguration();

} // namespace config

namespace fs_utils
{

std::string GenerateClusterUniqueFilename(const std::string &suffix);
int CreateDirectoryIfNotExists(const std::string &path);

} // namespace fs_utils

namespace resource
{
template <typename T> class TimerPool
{
  public:
    TimerPool() = default;
    TimerPool(const TimerPool &) = delete;
    TimerPool &operator=(const TimerPool &) = delete;

    template <bool Init = true> T *getObject()
    {
        std::lock_guard<std::mutex> lock(mutex_);

        T *obj = pool_.empty() ? nullptr : pool_.front();
        if (obj)
        {
            pool_.pop_front();
        }

        return obj ? obj : (Init ? new T() : nullptr);
    }

    void returnObject(T *obj, int *size)
    {
        if (!obj)
        {
            if (size)
                *size = 0;
            return;
        }

        std::lock_guard<std::mutex> lock(mutex_);
        pool_.push_back(obj);
        if (size)
            *size = static_cast<int>(pool_.size());
    }

    void clear()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto obj : pool_)
        {
            delete obj;
        }
        pool_.clear();
    }

    ~TimerPool() { clear(); }

  private:
    std::deque<T *> pool_;
    std::mutex mutex_;
};

} // namespace resource

namespace env
{

class EnvVarRegistry
{
  public:
    using VarType = std::variant<int, bool, std::string>;

    static std::string_view DEFAULT_VALUE_STRING;
    static int DEFAULT_VALUE_INT;
    static bool DEFAULT_VALUE_BOOL;

    static void RegisterEnv(const std::string &name, VarType default_value)
    {
        auto &registry = GetRegistryManager();
        LOG(INFO) << "[ENV] Register ENV " << name << " with default "
                  << VariantToString(default_value) << std::endl;
        registry[name] = std::move(default_value);
    }

    // Get an env var value, with optional printing
    template <typename T> static T GetEnvVar(const std::string &name)
    {
        static_assert(is_supported_type<T>(),
                      "Unsupported type for environment variable");

        auto &registry = GetRegistryManager();
        bool set = false;

        // Try to get from environment first
        T result = getEnvInner<T>(name, &set);
        if (set)
        {
            LOG(INFO) << "[ENV] Get " << name << "=" << result
                      << " from environment" << std::endl;
            return result;
        }

        // Try to get from registered defaults
        if (auto it = registry.find(name); it != registry.end())
        {
            if (const T *val = std::get_if<T>(&it->second))
            {
                LOG(INFO) << "[ENV] Get " << name << "=" << *val
                          << " from register default" << std::endl;
                return *val;
            }
            LOG(FATAL) << "[ENV] Wrong data type in `GetEnvVar`" << std::endl;
        }

        // Fall back to static default
        result = getDefault<T>();
        LOG(WARNING) << "[ENV] Get not register env " << name << "=" << result
                     << " from default" << std::endl;
        return result;
    }

    template <typename T>
    static inline auto convert_to_variant(const T &s)
        -> std::enable_if_t<std::is_constructible_v<std::string, T>, VarType>
    {
        return std::string(s);
    }

    template <typename T>
    static inline auto convert_to_variant(const T &val)
        -> std::enable_if_t<!std::is_constructible_v<std::string, T>, VarType>
    {
        return val;
    }

  private:
    template <typename T> static constexpr bool is_supported_type()
    {
        return std::is_same_v<T, bool> || std::is_same_v<T, int> ||
               std::is_same_v<T, std::string>;
    }

    static std::string toLower(const std::string &str)
    {
        std::string lower;
        lower.reserve(str.size());
        std::transform(str.begin(), str.end(), std::back_inserter(lower),
                       [](unsigned char c) { return std::tolower(c); });
        return lower;
    }

    // 值解析器
    template <typename T> static T parseEnvValue(const char *env)
    {
        if constexpr (std::is_same_v<T, int>)
        {
            try
            {
                return std::stoi(env);
            }
            catch (...)
            {
                return DEFAULT_VALUE_INT;
            }
        }
        else if constexpr (std::is_same_v<T, bool>)
        {
            std::string lower = toLower(env);
            if (lower == "true" || lower == "1")
                return true;
            if (lower == "false" || lower == "0")
                return false;
            return std::stoi(env) != 0;
        }
        else if constexpr (std::is_same_v<T, std::string>)
        {
            return env;
        }
    }

    // Get value from real environment
    template <typename T>
    static T getEnvInner(const std::string &env_name, bool *set)
    {
        const char *env = std::getenv(env_name.c_str());
        if (!env)
        {
            *set = false;
            return {};
        }

        *set = true;
        return parseEnvValue<T>(env);
    }

    // Default values for fallback
    template <typename T> static T getDefault()
    {
        if constexpr (std::is_same_v<T, int>)
        {
            return DEFAULT_VALUE_INT;
        }
        else if constexpr (std::is_same_v<T, bool>)
        {
            return DEFAULT_VALUE_BOOL;
        }
        else if constexpr (std::is_same_v<T, std::string>)
        {
            return std::string(DEFAULT_VALUE_STRING);
        }
    }

    static inline std::unordered_map<std::string, VarType> &GetRegistryManager()
    {
        static std::unordered_map<std::string, VarType> registry_manager;
        return registry_manager;
    }

    static std::string VariantToString(const VarType &var)
    {
        return std::visit(
            [](const auto &value)
            {
                std::stringstream ss;
                ss << value;
                return ss.str();
            },
            var);
    }
};

#define REGISTER_ENVIRONMENT_VARIABLE(name, value)                             \
    ::systrace::util::env::EnvVarRegistry::RegisterEnv(                        \
        name,                                                                  \
        ::systrace::util::env::EnvVarRegistry::convert_to_variant(value))

void REGISTER_ENV();

} // namespace env
void InitializeSystemUtilities();
} // namespace util
} // namespace systrace