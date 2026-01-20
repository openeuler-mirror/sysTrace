#pragma once
#include <nlohmann/json.hpp>
#include <string>
#include <atomic>

using json = nlohmann::json;

class ICollector {
  public:
    virtual ~ICollector() = default;
    virtual std::string get_id() const {
        return pluginName_ ? pluginName_ : "unknown";
    }

virtual bool start(const json &params, int duration) = 0;
    virtual void stop() = 0;

  protected:
    std::atomic<bool> active_{false};
    const char *pluginName_;

};