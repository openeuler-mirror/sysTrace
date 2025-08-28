#ifndef SHARED_CONSTANTS_H
#define SHARED_CONSTANTS_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <pthread.h>
#include <stdbool.h>
#include <time.h>

#define SHM_NAME "/sysTrace_shared_mem"
#define SYS_TRACE_ROOT_DIR "/home/sysTrace/"
    extern int global_stage_id;
    extern int global_stage_type;

    typedef struct
    {
        bool g_dump_L0;
        bool g_dump_L1;
        bool g_dump_L2;
        bool g_dump_L3;
        float g_dump_L1_interval;
        float g_dump_L2_interval;
        float g_dump_L3_interval;
        bool g_L1_timer_active;
        bool g_L2_timer_active;
        bool g_L3_timer_active;
        bool dumped_L1; // Indicates if L1 has been dumped
        bool dumped_L2; // Indicates if L2 has been dumped
        bool dumped_L3; // Indicates if L3 has been dumped
        bool need_dump_L1_once; // Indicates if L1 dump is needed once
        bool need_dump_L2_once; // Indicates if L2 dump is needed once
        bool need_dump_L3_once; // Indicates if L3 dump is needed once
        time_t g_L1_start_time;
        time_t g_L2_start_time;
        time_t g_L3_start_time;
        pthread_mutex_t g_trace_mutex;
        bool initialized; 
    } SharedData;

    int init_shared_memory();

    SharedData *get_shared_data();

    void cleanup_shared_memory();
    bool checkAndUpdateTimer(int level);
    bool need_dump_L1_once();
    bool need_dump_L2_once();

#ifdef __cplusplus
}
#endif

#endif // SHARED_CONSTANTS_H