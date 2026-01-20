#pragma once
#include <nlohmann/json.hpp>
#include <string>

using json = nlohmann::json;

class ICollector {
  public:
    virtual ~ICollector() = default;
    virtual std::string get_id() const = 0;
    virtual bool start(const json &params) = 0;
    virtual void stop() = 0;

  protected:
    bool active_ = false;
};