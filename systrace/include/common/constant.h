#pragma once
#include <stdbool.h>

#ifndef SYS_TRACE_ROOT_DIR
#define SYS_TRACE_ROOT_DIR "/home/sysTrace/"
#endif
inline bool checkAndUpdateTimer(int level) {
    return true;
};

#ifdef __cplusplus
extern "C" {
#endif

extern int global_stage_id;
extern int global_stage_type;

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
#include <string>
#include <string_view>
#include <cstddef>

namespace systrace
{
namespace constant
{
struct Cli {
    static constexpr const char* KEY_PATH   = "path";
    static constexpr const char* KEY_ACTION = "action";
    static constexpr const char* KEY_PARAMS = "params";

    static constexpr const char* ACT_ENABLE  = "enable";
    static constexpr const char* ACT_DISABLE = "disable";

    static constexpr const char* SOCK_DIR    = "/tmp/";
    static constexpr const char* SOCK_PREFIX = "sysTrace_";
    static constexpr const char* SOCK_EXT    = ".sock";
    
    static constexpr size_t MAX_BUF_SIZE = 1024;
};

struct TorchTraceConstant
{
  public:
    static constexpr int DEFAULT_TRACE_COUNT = 1000;
    static constexpr std::string_view DEFAULT_TRACE_DUMP_PATH = SYS_TRACE_ROOT_DIR "timeline";
};

} // namespace constant
} // namespace systrace

#else
#include <stddef.h>
#endif