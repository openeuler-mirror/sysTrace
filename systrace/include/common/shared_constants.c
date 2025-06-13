#include "shared_constants.h"
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static SharedData *shared_data = NULL;
static int shm_fd = -1;

int init_shared_memory()
{
    shm_fd = shm_open(SHM_NAME, O_CREAT | O_RDWR, 0666);
    if (shm_fd == -1)
    {
        perror("shm_open failed");
        return -1;
    }

    if (ftruncate(shm_fd, sizeof(SharedData)) == -1)
    {
        perror("ftruncate failed");
        close(shm_fd);
        return -1;
    }

    shared_data = mmap(NULL, sizeof(SharedData), PROT_READ | PROT_WRITE,
                       MAP_SHARED, shm_fd, 0);
    if (shared_data == MAP_FAILED)
    {
        perror("mmap failed");
        close(shm_fd);
        return -1;
    }

    static pthread_mutexattr_t mutex_attr;
    if (pthread_mutexattr_init(&mutex_attr) != 0)
    {
        perror("pthread_mutexattr_init failed");
        return -1;
    }

    if (pthread_mutexattr_setpshared(&mutex_attr, PTHREAD_PROCESS_SHARED) != 0)
    {
        perror("pthread_mutexattr_setpshared failed");
        return -1;
    }

    if (pthread_mutex_init(&shared_data->g_trace_mutex, &mutex_attr) != 0)
    {
        perror("pthread_mutex_init failed");
        return -1;
    }

    shared_data->g_dump_L0 = true;
    shared_data->g_dump_L1 = false;
    shared_data->g_dump_L2 = false;
    shared_data->g_dump_L1_interval = 5;
    shared_data->g_dump_L2_interval = 5;
    shared_data->g_L1_timer_active = false;
    shared_data->g_L2_timer_active = false;
    shared_data->g_L1_start_time = 0;
    shared_data->g_L2_start_time = 0;
    shared_data->dumped_L1 = false;
    shared_data->dumped_L2 = false;
    shared_data->need_dump_L1_once = false;
    shared_data->need_dump_L2_once = false;
    return 0;
}

SharedData *get_shared_data()
{
    if (shared_data == NULL)
    {
        if (init_shared_memory() != 0)
        {
            return NULL;
        }
    }
    return shared_data;
}

void cleanup_shared_memory()
{
    if (shared_data != NULL)
    {
        munmap(shared_data, sizeof(SharedData));
        shared_data = NULL;
    }

    if (shm_fd != -1)
    {
        close(shm_fd);
        shm_fd = -1;
    }

    shm_unlink(SHM_NAME);
}

bool checkAndUpdateTimer(int level) {
    SharedData* shared_data = get_shared_data();
    if (!shared_data) {
        return false;
    }

    pthread_mutex_lock(&shared_data->g_trace_mutex);

    bool* dump_flag = NULL;
    unsigned int* interval = NULL;
    bool* timer_active = NULL;
    time_t* start_time = NULL;
    const char* level_name = "";
    bool *dumped = false;
    bool *need_dump_once = NULL;

    switch(level) {
        case 1:  // L1
            dump_flag = &shared_data->g_dump_L1;
            interval = &shared_data->g_dump_L1_interval;
            timer_active = &shared_data->g_L1_timer_active;
            start_time = &shared_data->g_L1_start_time;
            level_name = "L1";
            dumped = &shared_data->dumped_L1;
            need_dump_once = &shared_data->need_dump_L1_once;
            break;
        case 2:  // L2
            dump_flag = &shared_data->g_dump_L2;
            interval = &shared_data->g_dump_L2_interval;
            timer_active = &shared_data->g_L2_timer_active;
            start_time = &shared_data->g_L2_start_time;
            level_name = "L2";
            dumped = &shared_data->dumped_L2;
            need_dump_once = &shared_data->need_dump_L2_once;
            break;
        default:
            pthread_mutex_unlock(&shared_data->g_trace_mutex);
            return false;
    }

    bool result = false;
    
    if (*dump_flag && !*timer_active) {
        *start_time = time(NULL);
        *timer_active = true;
        result = true;
    }
    else if (*timer_active) {
        time_t now = time(NULL);
        double elapsed = difftime(now, *start_time) / 60;
        
        if (elapsed >= *interval) {
            *dump_flag = false;
            *timer_active = false;
            if (!dumped) {
                *need_dump_once = true;
            }
        } else {
            result = true;
        }
    }
    
    pthread_mutex_unlock(&shared_data->g_trace_mutex);
    
    return result;
}

bool need_dump_L1_once() {
    SharedData* shared_data = get_shared_data();
    if (!shared_data) {
        return false;
    }

    pthread_mutex_lock(&shared_data->g_trace_mutex);
    bool result = shared_data->need_dump_L1_once;
    pthread_mutex_unlock(&shared_data->g_trace_mutex);
    
    return result;
}

bool need_dump_L2_once() {
    SharedData* shared_data = get_shared_data();
    if (!shared_data) {
        return false;
    }

    pthread_mutex_lock(&shared_data->g_trace_mutex);
    bool result = shared_data->need_dump_L2_once;
    pthread_mutex_unlock(&shared_data->g_trace_mutex);

    return result;
}
