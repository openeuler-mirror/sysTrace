#include "mspti_tracker.hpp"
#include "../../include/utils/util.h"
#include <chrono>
#include <dlfcn.h>
#include <iostream>
#include <stdlib.h>

constexpr size_t MB = 1024 * 1024;
constexpr size_t ALIGN_SIZE = 8;

std::mutex MSPTITracker::mtx;
using namespace systrace::util;

inline uint8_t *align_buffer(uint8_t *buffer, size_t align) {
    return reinterpret_cast<uint8_t *>(
        (reinterpret_cast<uintptr_t>(buffer) + (align - 1)) & ~(align - 1));
}

MSPTITracker::MSPTITracker() {
    LOG_MODULE(INFO, "MSPTI") << "Logging initialized from preloaded library.";
    hcclFileWriter = std::make_unique<MSPTIHcclFileWriter>("mspti_activity");
    msptiSubscribe(&subscriber, nullptr, nullptr);
    msptiActivityRegisterCallbacks(UserBufferRequest, UserBufferComplete);
    mspti_monitor_thread = std::thread(&MSPTITracker::collect, this);
}

MSPTITracker::~MSPTITracker() {
    should_run_ = false;
    if (mspti_monitor_thread.joinable())
        mspti_monitor_thread.join();
    msptiActivityFlushAll(1);
    finish();
}

MSPTITracker &MSPTITracker::getInstance() {
    static MSPTITracker instance;
    return instance;
}

void MSPTITracker::setEventMask(uint32_t mask) {
    target_mask_.store(mask);
    if (mask == MSPTI_EVENT_NONE) {
        msptiActivityFlushAll(1);

        if (hcclFileWriter) {
            hcclFileWriter->flush();
        }
    }
}

void MSPTITracker::updateActivityState(uint32_t target, uint32_t bit,
                                       msptiActivityKind kind) {
    bool is_on = (current_mask_ & bit);
    bool should_on = (target & bit);
    if (should_on && !is_on) {
        msptiActivityEnable(kind);
        current_mask_ |= bit;
        LOG_MODULE(INFO, "MSPTI") << "Enabled Activity Kind: " << kind;
    } else if (!should_on && is_on) {
        msptiActivityDisable(kind);
        current_mask_ &= ~bit;
        LOG_MODULE(INFO, "MSPTI") << "Disabled Activity Kind: " << kind;
    }
}

void MSPTITracker::collect() {
    while (should_run_) {
        uint32_t target = target_mask_.load();
        if (target != current_mask_) {
            std::lock_guard<std::mutex> lock(mtx);
            updateActivityState(target, MSPTI_EVENT_MARKER,
                                MSPTI_ACTIVITY_KIND_MARKER);
            updateActivityState(target, MSPTI_EVENT_KERNEL,
                                MSPTI_ACTIVITY_KIND_KERNEL);
            updateActivityState(target, MSPTI_EVENT_API,
                                MSPTI_ACTIVITY_KIND_API);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

void MSPTITracker::finish() {
    if (hcclFileWriter)
        hcclFileWriter->stopWriter();
}

void MSPTITracker::readActivityMarker(msptiActivityMarker *activity) {
    if (hcclFileWriter)
        hcclFileWriter->bufferMarkerActivity(activity);
}
void MSPTITracker::readActivityKernel(msptiActivityKernel *activity) {
    if (hcclFileWriter)
        hcclFileWriter->bufferKernelActivity(activity);
}
void MSPTITracker::readActivityApi(msptiActivityApi *activity) {
    if (hcclFileWriter)
        hcclFileWriter->bufferApiActivity(activity);
}

void MSPTITracker::UserBufferRequest(uint8_t **buffer, size_t *size,
                                     size_t *maxNumRecords) {
    auto &instance = getInstance();
    std::lock_guard<std::mutex> lock(mtx);
    size_t buffer_size = 2 * MB;
    instance.requestedCount.fetch_add(1);
    uint8_t *pBuffer = (uint8_t *)malloc(buffer_size + ALIGN_SIZE);
    *buffer = align_buffer(pBuffer, ALIGN_SIZE);
    *size = buffer_size;
    *maxNumRecords = 0;
}

void MSPTITracker::UserBufferComplete(uint8_t *buffer, size_t size,
                                      size_t validSize) {
    auto &instance = getInstance();
    if (validSize > 0) {
        msptiActivity *pRecord = nullptr;
        msptiResult status = MSPTI_SUCCESS;
        do {
            status = msptiActivityGetNextRecord(buffer, validSize, &pRecord);
            if (status == MSPTI_SUCCESS) {
                if (pRecord->kind == MSPTI_ACTIVITY_KIND_MARKER)
                    instance.readActivityMarker((msptiActivityMarker *)pRecord);
                else if (pRecord->kind == MSPTI_ACTIVITY_KIND_KERNEL)
                    instance.readActivityKernel((msptiActivityKernel *)pRecord);
                else if (pRecord->kind == MSPTI_ACTIVITY_KIND_API)
                    instance.readActivityApi((msptiActivityApi *)pRecord);
            }
        } while (status == MSPTI_SUCCESS);
    }
    free(buffer);
}