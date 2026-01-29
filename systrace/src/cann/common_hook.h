#ifndef COMMON_HOOK_H
#define COMMON_HOOK_H
#define _GNU_SOURCE
#include "../../include/utils/TimeUtil.hpp"
#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#if defined(__aarch64__)
#include "../../thirdparty/aarch64/libunwind/libunwind.h"
#elif defined(__x86_64__)
#include "../../thirdparty/x86_64/libunwind/libunwind.h"
#else
#error "Unsupported architecture - only aarch64 and x86_64 are supported"
#endif

#define LOG_INTERVAL_SEC 5
#define LOG_ITEMS_MIN 10
#define PATH_LEN 256
#define JSON "json"
#define PB "pb"

extern pid_t g_hooked_pid;
const char *get_so_name(uint64_t ip);
unw_word_t get_so_base(unw_word_t addr);
void get_log_filename(char *buf, size_t buf_size, const char *path_suffix,
                      const char *ext);
void *load_symbol(void *lib, const char *symbol_name);
void common_init_key(pthread_key_t *key, pthread_once_t *once,
                     void *(*alloc_func)(void), void (*free_func)(void *));
void common_atexit(void (*exit_handler)(void));

#endif // COMMON_HOOK_H
