#pragma once
#include "json_file_writer.hpp"
#include "mspti.h"
#include <atomic>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

enum MsptiEventMask : uint32_t {
    MSPTI_EVENT_NONE = 0,
    MSPTI_EVENT_MARKER = 1 << 0,
    MSPTI_EVENT_KERNEL = 1 << 1,
    MSPTI_EVENT_API = 1 << 2
};

class MSPTITracker {
  private:
    static std::mutex mtx;

    msptiSubscriberHandle subscriber;
    std::unique_ptr<MSPTIHcclFileWriter> hcclFileWriter;
    std::atomic<int> requestedCount{0};
    std::thread mspti_monitor_thread;
    std::atomic<bool> should_run_{true};

    std::atomic<uint32_t> target_mask_{MSPTI_EVENT_NONE};
    uint32_t current_mask_{MSPTI_EVENT_NONE};

    MSPTITracker();
    ~MSPTITracker();

    void updateActivityState(uint32_t target, uint32_t bit,
                             msptiActivityKind kind);

  public:
    MSPTITracker(const MSPTITracker &) = delete;
    MSPTITracker &operator=(const MSPTITracker &) = delete;

    static MSPTITracker &getInstance();

    void finish();
    void setEventMask(uint32_t mask);

    void readActivityMarker(msptiActivityMarker *activity);
    void readActivityKernel(msptiActivityKernel *activity);
    void readActivityApi(msptiActivityApi *activity);

    static void UserBufferRequest(uint8_t **buffer, size_t *size,
                                  size_t *maxNumRecords);
    static void UserBufferComplete(uint8_t *buffer, size_t size,
                                   size_t validSize);
    void collect();
};