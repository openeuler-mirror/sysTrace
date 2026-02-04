#include "hook.h"
#include "../../include/log/logging.h"
#include "../src/trace/systrace_manager.h"
#include <Python.h>
#include <chrono>
#include <cstdlib>
#include <dlfcn.h>
#include <iostream>
#include <mutex>
#include <stdio.h>
#include <string>
#include <thread>
#include <unistd.h>

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
    const char *cmd = "python3 -c \"import sys, os, sysconfig; "
                      "l=sysconfig.get_config_var('LIBDIR'); "
                      "s=sysconfig.get_config_var('INSTSONAME'); "
                      "p=os.path.join(l, s) if l and s else ''; "
                      "print(p if p and os.path.exists(p) and ('.so' in s or "
                      "'.dylib' in s) else sys.executable)\" 2>&1";
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
        std::strncpy(g_python_lib_path, result.c_str(),
                     sizeof(g_python_lib_path) - 1);
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

void set_rank() {
    int local_rank = -1;
    int global_rank = -1;
    bool success = false;

    const int max_retries = 600;
    const int sleep_ms = 100;

    for (int i = 0; i < max_retries; ++i) {
        PyGILState_STATE gstate = PyGILState_Ensure();

        PyObject *parallel_mod =
            PyImport_ImportModule("vllm.distributed.parallel_state");
        if (parallel_mod) {
            PyObject *get_group_func =
                PyObject_GetAttrString(parallel_mod, "get_world_group");

            if (get_group_func && PyCallable_Check(get_group_func)) {
                PyObject *world_group =
                    PyObject_CallObject(get_group_func, nullptr);

                if (world_group && world_group != Py_None) {
                    PyObject *py_rank =
                        PyObject_GetAttrString(world_group, "rank");
                    PyObject *py_local_rank =
                        PyObject_GetAttrString(world_group, "local_rank");

                    if (py_rank && py_rank != Py_None && py_local_rank &&
                        py_local_rank != Py_None) {
                        global_rank = (int)PyLong_AsLong(py_rank);
                        local_rank = (int)PyLong_AsLong(py_local_rank);
                        success = true;
                    }

                    Py_XDECREF(py_rank);
                    Py_XDECREF(py_local_rank);
                    Py_DECREF(world_group);
                }
                Py_XDECREF(get_group_func);
            }
            Py_DECREF(parallel_mod);
        } else {
            PyErr_Clear();
        }

        PyGILState_Release(gstate);

        if (success) {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(sleep_ms));
    }

    if (success) {
        std::string lr_str = std::to_string(local_rank);
        std::string gr_str = std::to_string(global_rank);

        setenv("LOCAL_RANK", lr_str.c_str(), 1);
        setenv("RANK", gr_str.c_str(), 1);
    }
}

static std::once_flag global_delayed_init_flag;

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

void async_delayed_init() {
    try {

        if (!(check_rank_env() && check_local_rank_env())) {
            set_rank();
        }
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

#define HOOKED_FUNCTION(func_ptr, func_name, ...)                              \
    do {                                                                       \
        std::call_once(global_delayed_init_flag, []() {                        \
            std::thread t(async_delayed_init);                                 \
            t.detach();                                                        \
        });                                                                    \
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