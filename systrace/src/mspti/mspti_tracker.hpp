#pragma once

#include "json_file_writer.h"

#include <atomic>
#include <memory>
#include <mutex>
#include <atomic>
#include <thread>
#include <unordered_set>
#include <unordered_map>
#include <string>
#include <vector>

class MSPTITracker {
public:
    static MSPTITracker& getInstance();
    ~MSPTITracker();

    void finish();
    void readActivityMarker(msptiActivityMarker *activity);

private:
    MSPTITracker();
    
    static std::mutex mtx;
    static std::atomic<int> requestedCount;
    
    std::unique_ptr<MSPTIHcclFileWriter> hcclFileWriter;
    msptiSubscriberHandle subscriber = nullptr;
    bool is_initialized = false;
    
    static void configMonitorThread();
    static void startConfigMonitor();
    static void stopConfigMonitor();
    static void parseConfigFromFile();
    static void updateTrackingState();
    static std::vector<std::string> splitConfigString(const std::string& str);
    
    bool isActivityEnabled(msptiActivityKind kind);
    bool isTrackingEnabled() { return tracking_enabled.load(); }
    
    static std::atomic<bool> stop_config_monitor;
    static std::thread config_monitor_thread;
    static std::unordered_set<msptiActivityKind> enabled_activities;
    static std::atomic<bool> tracking_enabled;
    
    static const std::unordered_map<std::string, msptiActivityKind> activity_map;
    
    static void UserBufferRequest(uint8_t **buffer, size_t *size, size_t *maxNumRecords);
    static void UserBufferComplete(uint8_t *buffer, size_t size, size_t validSize);
    
    MSPTITracker(const MSPTITracker&) = delete;
    MSPTITracker& operator=(const MSPTITracker&) = delete;
};
