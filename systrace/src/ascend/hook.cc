#include "hook.h"
#include "../../include/log/logging.h"
#include "../src/trace/systrace_manager.h"
#include <array>
#include <chrono>
#include <cstdlib>
#include <dlfcn.h>
#include <iostream>
#include <memory>
#include <mutex>
#include <stdio.h>
#include <string>
#include <thread>
#include <unistd.h>

// Minimal forward declarations for Python C API types,
// used with dynamically-resolved symbols (no link-time libpython dependency).
struct _object;
typedef struct _object PyObject;
typedef int PyGILState_STATE;

static std::string get_mindspore_lib_path() {
    const char *cmd = "python -c \"import mindspore as ms; import os; "
                      "print(os.path.join(os.path.dirname(ms.__file__), "
                      "'lib/libmindspore_backend.so'))\"";
    FILE *pipe = popen(cmd, "r");
    if (!pipe)
        return "";

    char buffer[1024];
    std::string result;
    if (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        result = buffer;
        result.erase(result.find_last_not_of("\n") + 1);
    }
    pclose(pipe);
    return result;
}

static void find_python_path_cmd() {
    const char *cmd = "python -c \"import sys, os, sysconfig; "
                      "l=sysconfig.get_config_var('LIBDIR'); "
                      "s=sysconfig.get_config_var('INSTSONAME'); "
                      "p=os.path.join(l, s) if l and s else ''; "
                      "print(p if p and os.path.exists(p) and ('.so' in s "
                      ") else sys.executable)\" 2>&1";
    std::array<char, 512> buffer;
    std::string result;
    FILE *pipe_ptr = popen(cmd, "r");
    if (!pipe_ptr) {
        return;
    }
    std::unique_ptr<FILE, void (*)(FILE *)> pipe(pipe_ptr, [](FILE *f) {
        if (f)
            pclose(f);
    });
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }
    result.erase(result.find_last_not_of("\r\n ") + 1);
    if (!result.empty()) {
        char *real_path = realpath(result.c_str(), nullptr);
        if (real_path) {
            std::strncpy(g_python_lib_path, real_path,
                         sizeof(g_python_lib_path) - 1);
            free(real_path);
        } else {
            std::strncpy(g_python_lib_path, result.c_str(),
                         sizeof(g_python_lib_path) - 1);
        }
        g_python_lib_path[sizeof(g_python_lib_path) - 1] = '\0';
    } else {
        systrace_log_error("Hook", "Failed to auto-detect python path!",
                           dlerror());
    }
}

static int set_libc_so_path(int pid, char *elf_path, int size,
                            const char *so_keyword) {
    char map_file[512];
    char buf[512];
    snprintf(map_file, sizeof(map_file), "/proc/%d/maps", pid);

    FILE *fp = fopen(map_file, "r");
    if (!fp)
        return -1;

    while (fgets(buf, sizeof(buf), fp)) {
        char so_path[512] = {0};
        if (sscanf(buf, "%*x-%*x %*s %*s %*s %*s %511s", so_path) != 1)
            continue;

        if (strstr(so_path, so_keyword)) {
            snprintf(elf_path, size, "/proc/%d/root%s", pid, so_path);
            fclose(fp);
            return 0;
        }
    }
    fclose(fp);
    return -1;
}

extern "C" void _ZN9mindspore11distributed10InitializeEv() {
    std::call_once(init_flag, []() {
        std::string so_path = get_mindspore_lib_path();
        if (so_path.empty()) {
            LOG_MODULE(ERROR, "Hook")
                << "Failed to find libmindspore_backend.so\n";
            return;
        }

        void *handle = dlopen(so_path.c_str(), RTLD_LAZY);
        if (!handle) {
            LOG_MODULE(ERROR, "Hook")
                << "Failed to dlopen " << so_path << ": " << dlerror();
            return;
        }

        original_Initialize = (void (*)())dlsym(
            handle, "_ZN9mindspore11distributed10InitializeEv");
        if (!original_Initialize) {
            LOG_MODULE(ERROR, "Hook")
                << "Failed to dlsym _ZN9mindspore11distributed10InitializeEv: "
                << dlerror();
            dlclose(handle);
            return;
        }
        ::systrace::SysTrace::getInstance();
    });

    if (!original_Initialize) {
        LOG_MODULE(ERROR, "Hook") << "Original function not loaded";
        return;
    }
    original_Initialize();
}

#ifdef __cplusplus
extern "C" {
#endif

char g_python_lib_path[512] = {0};
char g_libc_path[512] = {0};
static void *load_symbol(const char *func_name) {
    if (!g_hal_lib) {
        g_hal_lib = dlopen("libascendcl.so", RTLD_LAZY);
        if (!g_hal_lib) {
            systrace_log_error("Hook", "Failed to dlopen libascendcl.so: %s",
                               dlerror());
            return nullptr;
        }
    }

    void *func = dlsym(g_hal_lib, func_name);
    if (!func) {
        std::cout << "[Hook]"
                  << "Failed to dlsym: " << func_name << " " << dlerror()
                  << std::endl;
    } else {
        std::cout << "[Hook]"
                  << "Successfully hooked " << func_name << std::endl;
    }
    return func;
}

struct PythonApi {
    PyGILState_STATE (*PyGILState_Ensure)(void);
    void (*PyGILState_Release)(PyGILState_STATE);
    PyObject *(*PyImport_ImportModule)(const char *);
    PyObject *(*PyObject_GetAttrString)(PyObject *, const char *);
    int (*PyCallable_Check)(PyObject *);
    PyObject *(*PyObject_CallObject)(PyObject *, PyObject *);
    long (*PyLong_AsLong)(PyObject *);
    void (*PyErr_Clear)(void);
    void (*Py_DecRef)(PyObject *);
};

static PythonApi g_python_api = {};

static bool init_python_api() {
    static bool initialized = false;
    static bool ok = false;
    if (initialized) {
        return ok;
    }
    initialized = true;

    void *handle = dlopen(nullptr, RTLD_LAZY);
    if (!handle) {
        return false;
    }

    bool success = true;
#define LOAD_PY_FUNC(name)                                                     \
    do {                                                                       \
        g_python_api.name = reinterpret_cast<decltype(g_python_api.name)>(     \
            dlsym(handle, #name));                                             \
        if (!g_python_api.name) {                                              \
            success = false;                                                   \
        }                                                                      \
    } while (0)

    LOAD_PY_FUNC(PyGILState_Ensure);
    LOAD_PY_FUNC(PyGILState_Release);
    LOAD_PY_FUNC(PyImport_ImportModule);
    LOAD_PY_FUNC(PyObject_GetAttrString);
    LOAD_PY_FUNC(PyCallable_Check);
    LOAD_PY_FUNC(PyObject_CallObject);
    LOAD_PY_FUNC(PyLong_AsLong);
    LOAD_PY_FUNC(PyErr_Clear);
    LOAD_PY_FUNC(Py_DecRef);

#undef LOAD_PY_FUNC

    ok = success;
    return ok;
}

bool parse_rank_from_cmdline(int &local_rank, int &global_rank) {
    FILE *fp = fopen("/proc/self/cmdline", "r");
    if (!fp) {
        return false;
    }

    char cmdline[10240] = {0};
    size_t len = fread(cmdline, 1, sizeof(cmdline) - 1, fp);
    fclose(fp);

    for (size_t i = 0; i < len; i++) {
        if (cmdline[i] == '\0') {
            cmdline[i] = ' ';
        }
    }

    char *node_rank_ptr = strstr(cmdline, "--node_rank=");
    if (node_rank_ptr) {
        node_rank_ptr += strlen("--node_rank=");
        global_rank = atoi(node_rank_ptr);
    }

    char *devices_ptr = strstr(cmdline, "--devices=");
    if (devices_ptr) {
        devices_ptr += strlen("--devices=");
        if (strncmp(devices_ptr, "npu:", 4) == 0) {
            local_rank = atoi(devices_ptr + 4);
        }
    }

    return global_rank >= 0 && local_rank >= 0;
}

void set_rank_for_xllm() {
    int local_rank = -1;
    int global_rank = -1;

    if (parse_rank_from_cmdline(local_rank, global_rank)) {

        std::string lr_str = std::to_string(local_rank);
        std::string gr_str = std::to_string(global_rank);

        setenv("LOCAL_RANK", lr_str.c_str(), 1);
        setenv("RANK", gr_str.c_str(), 1);

    } else {
        std::cout << "[Hook][XLLM] Failed to get XLLM rank from all sources"
                  << std::endl;
    }
}

void set_rank_for_vllm() {
    if (!init_python_api()) {
        return;
    }

    int local_rank = -1;
    int global_rank = -1;
    bool success = false;

    const int max_retries = 600;
    const int sleep_ms = 100;

    for (int i = 0; i < max_retries; ++i) {
        PyGILState_STATE gstate = g_python_api.PyGILState_Ensure();

        PyObject *parallel_mod = g_python_api.PyImport_ImportModule(
            "vllm.distributed.parallel_state");
        if (parallel_mod) {
            PyObject *get_group_func = g_python_api.PyObject_GetAttrString(
                parallel_mod, "get_world_group");

            if (get_group_func &&
                g_python_api.PyCallable_Check(get_group_func)) {
                PyObject *world_group =
                    g_python_api.PyObject_CallObject(get_group_func, nullptr);

                if (world_group) {
                    PyObject *py_rank = g_python_api.PyObject_GetAttrString(
                        world_group, "rank");
                    PyObject *py_local_rank =
                        g_python_api.PyObject_GetAttrString(world_group,
                                                            "local_rank");

                    if (py_rank && py_local_rank) {
                        long gr = g_python_api.PyLong_AsLong(py_rank);
                        long lr = g_python_api.PyLong_AsLong(py_local_rank);
                        if (gr >= 0 && lr >= 0) {
                            global_rank = static_cast<int>(gr);
                            local_rank = static_cast<int>(lr);
                            success = true;
                        }
                    }

                    if (py_rank) {
                        g_python_api.Py_DecRef(py_rank);
                    }
                    if (py_local_rank) {
                        g_python_api.Py_DecRef(py_local_rank);
                    }
                    g_python_api.Py_DecRef(world_group);
                }

                if (get_group_func) {
                    g_python_api.Py_DecRef(get_group_func);
                }
            }
            g_python_api.Py_DecRef(parallel_mod);
        } else if (g_python_api.PyErr_Clear) {
            g_python_api.PyErr_Clear();
        }

        g_python_api.PyGILState_Release(gstate);

        if (success) {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(sleep_ms));
    }

    if (!success) {
        return;
    }

    std::string lr_str = std::to_string(local_rank);
    std::string gr_str = std::to_string(global_rank);

    setenv("LOCAL_RANK", lr_str.c_str(), 1);
    setenv("RANK", gr_str.c_str(), 1);
}

bool check_rank_env() {
    const char *r_str = getenv("RANK");
    if (!r_str)
        r_str = getenv("RANK_ID");
    if (!r_str)
        return false;
    return true;
}

bool check_local_rank_env() {
    const char *lr_str = getenv("LOCAL_RANK");
    if (!lr_str)
        lr_str = getenv("DEVICE_ID");
    if (!lr_str)
        return false;
    return true;
}

std::string get_process_cmdline(pid_t pid) {
    std::string cmdline_path = "/proc/" + std::to_string(pid) + "/cmdline";
    std::string cmdline;

    int fd = open(cmdline_path.c_str(), O_RDONLY);
    if (fd == -1) {
        return "";
    }

    char buffer[4096];
    ssize_t read_size = read(fd, buffer, sizeof(buffer) - 1);
    close(fd);

    if (read_size <= 0) {
        return "";
    }

    buffer[read_size] = '\0';
    std::stringstream ss;
    for (ssize_t i = 0; i < read_size; ++i) {
        if (buffer[i] == '\0') {
            if (ss.tellp() > 0 && ss.str().back() != ' ') {
                ss << " ";
            }
        } else {
            ss << buffer[i];
        }
    }

    cmdline = ss.str();
    cmdline.erase(0, cmdline.find_first_not_of(" "));
    cmdline.erase(cmdline.find_last_not_of(" ") + 1);

    return cmdline;
}

pid_t get_parent_pid(pid_t pid) {
    std::string stat_path = "/proc/" + std::to_string(pid) + "/stat";
    std::ifstream stat_file(stat_path);
    if (!stat_file.is_open()) {
        return -1;
    }

    std::string line;
    std::getline(stat_file, line);
    stat_file.close();

    std::istringstream iss(line);
    std::string dummy;
    pid_t ppid;

    iss >> dummy >> dummy >> dummy >> ppid;
    return ppid;
}

bool is_process_spawned_by_vllm() {
    pid_t current_pid = getpid();
    const int MAX_DEPTH = 10;
    int depth = 0;

    while (current_pid > 1 && depth < MAX_DEPTH) {
        std::string cmdline = get_process_cmdline(current_pid);
        if (!cmdline.empty()) {
            std::string lower_cmdline = cmdline;
            std::transform(lower_cmdline.begin(), lower_cmdline.end(),
                           lower_cmdline.begin(), ::tolower);
            if (lower_cmdline.find("vllm") != std::string::npos) {
                return true;
            }
        }

        current_pid = get_parent_pid(current_pid);
        depth++;
    }

    return false;
}

bool is_process_spawned_by_xllm() {
    pid_t current_pid = getpid();
    const int MAX_DEPTH = 10;
    int depth = 0;

    while (current_pid > 1 && depth < MAX_DEPTH) {
        std::string cmdline = get_process_cmdline(current_pid);
        if (!cmdline.empty()) {
            std::string lower_cmdline = cmdline;
            std::transform(lower_cmdline.begin(), lower_cmdline.end(),
                           lower_cmdline.begin(), ::tolower);
            if (lower_cmdline.find("xllm") != std::string::npos) {
                return true;
            }
        }

        current_pid = get_parent_pid(current_pid);
        depth++;
    }

    return false;
}

void set_rank() {
    if (is_process_spawned_by_vllm()) {
        set_rank_for_vllm();
    } else if (is_process_spawned_by_xllm()) {
        set_rank_for_xllm();
    }
}
void init_systrace() {
    try {
        const char *log_path_env = std::getenv("SYSTRACE_LOG_PATH");
        std::string log_path = (log_path_env && strlen(log_path_env) > 0)
                                   ? std::string(log_path_env)
                                   : "/var/log/sysTrace";
        ::systrace::setLoggingPath(log_path);

        ::systrace::SysTrace::getInstance();
    } catch (const std::exception &e) {
        systrace_log_error("Hook", "Delayed init failed: %s", e.what());
    }
}
static std::once_flag global_delayed_init_flag;

void async_delayed_init() {
    set_rank();
    init_systrace();
}

#define HOOKED_FUNCTION(func_ptr, func_name, ...)                              \
    do {                                                                       \
        if (!(check_rank_env() && check_local_rank_env())) {                   \
            if (is_process_spawned_by_vllm()) {                                \
                std::call_once(global_delayed_init_flag, []() {                \
                    std::thread t(async_delayed_init);                         \
                    t.detach();                                                \
                });                                                            \
            } else if (is_process_spawned_by_xllm()) {                         \
                std::call_once(global_delayed_init_flag,                       \
                               []() { async_delayed_init(); });                \
            } else {                                                           \
                std::call_once(global_delayed_init_flag,                       \
                               []() { init_systrace(); });                     \
            }                                                                  \
        } else {                                                               \
            std::call_once(global_delayed_init_flag,                           \
                           []() { init_systrace(); });                         \
        }                                                                      \
        if (!func_ptr) {                                                       \
            func_ptr = (decltype(func_ptr))load_symbol(func_name);             \
            if (!func_ptr)                                                     \
                return -1;                                                     \
        }                                                                      \
        return func_ptr(__VA_ARGS__);                                          \
    } while (0)

EXPOSE_API aclError aclInit(const char *configPath) {
    g_hooked_pid = getpid();
    find_python_path_cmd();
    set_libc_so_path(g_hooked_pid, g_libc_path, sizeof(g_libc_path), "libc.so");

    HOOKED_FUNCTION(orig_aclInit, "aclInit", configPath);
}

EXPOSE_API aclError aclrtMapMem(void *virPtr, size_t size, size_t offset,
                                aclrtDrvMemHandle handle, uint64_t flags) {
    HOOKED_FUNCTION(orig_aclrtMapMem, "aclrtMapMem", virPtr, size, offset,
                    handle, flags);
}

EXPOSE_API aclError aclrtLaunchKernel(aclrtFuncHandle func, int workDim,
                                      void **workGroup, size_t *localWorkSize,
                                      aclrtStream stream, void *event,
                                      void *config) {
    HOOKED_FUNCTION(orig_aclrtLaunchKernel, "aclrtLaunchKernel", func, workDim,
                    workGroup, localWorkSize, stream, event, config);
}

#ifdef __cplusplus
}
#endif