#pragma once
#define EXPOSE_API __attribute__((visibility("default")))

#define SETUP_SYMBOL_FOR_LOAD_LIBRARY(handle, symbol, func_ptr, func_type,     \
                                      msg)                                     \
    do                                                                         \
    {                                                                          \
        func_ptr = (func_type)dlsym(handle, symbol);                           \
        const char *dlsym_error = dlerror();                                   \
        if (dlsym_error)                                                       \
        {                                                                      \
            STLOG(WARNING) << "Load fn `" << symbol << "` error in " << msg    \
                           << dlsym_error;                                     \
            is_usable_ = false;                                                \
            return;                                                            \
        }                                                                      \
    } while (0)
