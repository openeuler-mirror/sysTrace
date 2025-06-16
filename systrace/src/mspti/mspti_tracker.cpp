#include "mspti_tracker.hpp"
#include <dlfcn.h>
#include <iostream>
#include <stdlib.h>
#include "../../include/common/util.h"

constexpr size_t KB = 1 * 1024;
constexpr size_t MB = 1 * 1024 * KB;
constexpr size_t ALIGN_SIZE = 8;

std::mutex MSPTITracker::mtx;
using namespace systrace::util;

inline uint8_t *align_buffer(uint8_t *buffer, size_t align)
{
    return reinterpret_cast<uint8_t *>(
        (reinterpret_cast<uintptr_t>(buffer) + (align - 1)) & ~(align - 1));
}

MSPTITracker::MSPTITracker()
{
    std::cout << "Logging initialized from preloaded library." << std::endl;
    std::string file_name = "hccl_activity-" + systrace::util::GetPrimaryIP() + "-.csv"; 
    hcclFileWriter =
        std::make_unique<MSPTIHcclFileWriter>(file_name);
    msptiSubscribe(&subscriber, nullptr, nullptr);
    msptiActivityRegisterCallbacks(UserBufferRequest, UserBufferComplete);
    mspti_monitor_thread = std::thread(&MSPTITracker::collect, this);
}

void MSPTITracker::collect()
{
    while (should_run_) {
        bool should_collect = checkAndUpdateTimer(1);
        if (should_collect && !is_collecting_.load()) {
            msptiActivityEnable(MSPTI_ACTIVITY_KIND_MARKER);
            is_collecting_.store(true);
        } 
        else if (!should_collect && is_collecting_.load()) {
            msptiActivityDisable(MSPTI_ACTIVITY_KIND_MARKER);
            is_collecting_.store(false);
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

MSPTITracker::~MSPTITracker()
{
    msptiActivityFlushAll(1);
    msptiActivityDisable(MSPTI_ACTIVITY_KIND_MARKER);
    finish();
    should_run_ = false;
    if (mspti_monitor_thread.joinable()) {
        mspti_monitor_thread.join();
    }
}

MSPTITracker &MSPTITracker::getInstance()
{
    static MSPTITracker instance;
    return instance;
}

void MSPTITracker::finish()
{
    std::cout << "Finishing MSPTI Tracker" << std::endl;
    if (hcclFileWriter)
    {
        hcclFileWriter->stopWriter();
    }
}

void MSPTITracker::readActivityMarker(msptiActivityMarker *activity)
{
    if (hcclFileWriter)
    {
        hcclFileWriter->bufferMarkerActivity(activity);
    }
}

void MSPTITracker::UserBufferRequest(uint8_t **buffer, size_t *size,
                                     size_t *maxNumRecords)
{
    auto &instance = getInstance();
    std::lock_guard<std::mutex> lock(mtx);
    constexpr uint32_t SIZE = (uint32_t)MB * 1;
    instance.requestedCount.fetch_add(1);
    uint8_t *pBuffer = (uint8_t *)malloc(SIZE + ALIGN_SIZE);
    *buffer = align_buffer(pBuffer, ALIGN_SIZE);
    *size = MB * 1;
    *maxNumRecords = 0;
}

void MSPTITracker::UserBufferComplete(uint8_t *buffer, size_t size,
                                      size_t validSize)
{
    auto &instance = getInstance();
    if (validSize > 0)
    {
        msptiActivity *pRecord = nullptr;
        msptiResult status = MSPTI_SUCCESS;
        do
        {
            std::lock_guard<std::mutex> lock(mtx);
            status = msptiActivityGetNextRecord(buffer, validSize, &pRecord);
            if (status == MSPTI_SUCCESS &&
                pRecord->kind == MSPTI_ACTIVITY_KIND_MARKER)
            {
                instance.readActivityMarker(
                    reinterpret_cast<msptiActivityMarker *>(pRecord));
            }
            else if (status == MSPTI_ERROR_MAX_LIMIT_REACHED)
            {
                break;
            }
        } while (status == MSPTI_SUCCESS);
    }
    free(buffer);
}