#include "hook.h"
#include "../src/trace/systrace_manager.h"
#include <cstdlib>
#include <dlfcn.h>
#include <iostream>

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