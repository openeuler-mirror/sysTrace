#include <dlfcn.h>
#include <stdio.h>
#include <mutex>
#include <cstdlib>
#include <iostream>
#include <string>
#include <unistd.h>
#include "../src/trace/systrace_manager.h"
#include "hook.h"

static std::string get_mindspore_lib_path() {
    const char* cmd = "python -c \"import mindspore as ms; import os; print(os.path.join(os.path.dirname(ms.__file__), 'lib/libmindspore_backend.so'))\"";
    FILE* pipe = popen(cmd, "r");
    if (!pipe) return "";

    char buffer[1024];
    std::string result;
    if (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        result = buffer;
        result.erase(result.find_last_not_of("\n") + 1);
    }
    pclose(pipe);
    return result;
}

extern "C" void _ZN9mindspore11distributed10InitializeEv() {
    std::call_once(init_flag, []() {
        std::string so_path = get_mindspore_lib_path();
        if (so_path.empty()) {
            fprintf(stderr, "[ERROR] Failed to find libmindspore_backend.so\n");
            return;
        }

        void* handle = dlopen(so_path.c_str(), RTLD_LAZY);
        if (!handle) {
            fprintf(stderr, "[ERROR] dlopen failed: %s\n", dlerror());
            return;
        }

        original_Initialize = (void (*)())dlsym(handle, "_ZN9mindspore11distributed10InitializeEv");
        if (!original_Initialize) {
            fprintf(stderr, "[ERROR] dlsym failed: %s\n", dlerror());
            return;
        }
        ::systrace::SysTrace::getInstance();
    });

    if (!original_Initialize) {
        fprintf(stderr, "[ERROR] Original function not loaded\n");
        return;
    }
    original_Initialize();
}

#ifdef __cplusplus
extern "C"
{
#endif

    static void *load_symbol(const char *func_name)
    {
        if (!g_hal_lib)
        {
            g_hal_lib = dlopen("libascendcl.so", RTLD_LAZY);
            if (!g_hal_lib)
            {
                fprintf(stderr, "[Hook] Failed to dlopen libascendcl.so: %s\n",
                        dlerror());
                return nullptr;
            }
        }

        void *func = dlsym(g_hal_lib, func_name);
        if (!func)
        {
            fprintf(stderr, "[Hook] Failed to dlsym %s: %s\n", func_name,
                    dlerror());
        }
        else
        {
            std::cout << "[Hook] Successfully hooked " << func_name
                      << std::endl;
        }
        return func;
    }

#define HOOKED_FUNCTION(func_ptr, func_name, ...)                              \
    if (!func_ptr)                                                             \
    {                                                                          \
        func_ptr = (decltype(func_ptr))load_symbol(func_name);                 \
        if (!func_ptr)                                                         \
            return -1;                                                         \
    }                                                                          \
    ::systrace::SysTrace::getInstance();                                       \
    return func_ptr(__VA_ARGS__);

    EXPOSE_API aclError aclInit(const char *configPath)
    {
        g_hooked_pid = getpid();
        HOOKED_FUNCTION(orig_aclInit, "aclInit", configPath);
    }

    EXPOSE_API aclError aclrtMapMem(void *virPtr, size_t size, size_t offset,
                                    aclrtDrvMemHandle handle, uint64_t flags)
    {
        HOOKED_FUNCTION(orig_aclrtMapMem, "aclrtMapMem", virPtr, size, offset,
                        handle, flags);
    }

    EXPOSE_API aclError aclrtLaunchKernel(aclrtFuncHandle func, int workDim,
                                          void **workGroup,
                                          size_t *localWorkSize,
                                          aclrtStream stream, void *event,
                                          void *config)
    {
        HOOKED_FUNCTION(orig_aclrtLaunchKernel, "aclrtLaunchKernel", func,
                        workDim, workGroup, localWorkSize, stream, event,
                        config);
    }

#ifdef __cplusplus
}
#endif