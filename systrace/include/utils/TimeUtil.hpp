#pragma once

#include <stdint.h>
#include <sys/time.h>
#include <time.h>

#ifdef __cplusplus

namespace systrace {
namespace util {
namespace time {

inline int64_t GetBootOffsetUs() {
    struct timespec real, mono;
    if (clock_gettime(CLOCK_REALTIME, &real) == 0 &&
        clock_gettime(CLOCK_MONOTONIC, &mono) == 0) {
        int64_t real_us = static_cast<int64_t>(real.tv_sec) * 1000000LL +
                          (real.tv_nsec / 1000);
        int64_t mono_us = static_cast<int64_t>(mono.tv_sec) * 1000000LL +
                          (mono.tv_nsec / 1000);
        return real_us - mono_us;
    }
    return 0;
}

inline uint64_t MonotonicNsToUtcUs(uint64_t mono_ns) {
    static const int64_t offset_us = GetBootOffsetUs();
    return (mono_ns / 1000) + offset_us;
}

inline uint64_t GetCurrentUtcUs() {
    struct timeval tv;
    gettimeofday(&tv, nullptr);
    return static_cast<uint64_t>(tv.tv_sec) * 1000000ULL +
           static_cast<uint64_t>(tv.tv_usec);
}

} // namespace time
} // namespace util
} // namespace systrace

extern "C" {
#endif

static inline uint64_t monotonic_ns_to_utc_us(uint64_t mono_ns) {
#ifdef __cplusplus
    return systrace::util::time::MonotonicNsToUtcUs(mono_ns);
#else
    struct timespec r, m;
    if (clock_gettime(CLOCK_REALTIME, &r) == 0 &&
        clock_gettime(CLOCK_MONOTONIC, &m) == 0) {
        int64_t off = ((int64_t)r.tv_sec - m.tv_sec) * 1000000LL +
                      (r.tv_nsec - m.tv_nsec) / 1000;
        return (mono_ns / 1000) + off;
    }
    return mono_ns / 1000;
#endif
}

static inline uint64_t get_current_utc_us(void) {
#ifdef __cplusplus
    return systrace::util::time::GetCurrentUtcUs();
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000ULL + (uint64_t)tv.tv_usec;
#endif
}

#ifdef __cplusplus
}
#endif