#include "mspti_tracker.hpp"
#include <dlfcn.h>
#include <iostream>
#include <stdlib.h>
#include <fstream>
#include <chrono>
#include <thread>
#include <mutex>
#include <atomic>
#include <unordered_set>
#include <unordered_map>
#include <string>
#include <vector>
#include <sstream>
#include <sys/stat.h>
#include "../../include/common/util.h"

constexpr size_t KB = 1 * 1024;
constexpr size_t MB = 1 * 1024 * KB;
constexpr size_t ALIGN_SIZE = 8;
#define LOG_PRINT(message, ...) \
    do { \
        printf(message, ##__VA_ARGS__); \
    } while (0)

std::mutex MSPTITracker::mtx;
std::atomic<int> MSPTITracker::requestedCount(0);
std::atomic<bool> MSPTITracker::stop_config_monitor(false);
std::thread MSPTITracker::config_monitor_thread;
std::unordered_set<msptiActivityKind> MSPTITracker::enabled_activities;
std::atomic<bool> MSPTITracker::tracking_enabled(false);

const std::string CONFIG_FILE = "/tmp/mspti_trace.config";

const std::unordered_map<std::string, msptiActivityKind> MSPTITracker::activity_map = {
    {"MSPTI_ACTIVITY_KIND_MARKER", MSPTI_ACTIVITY_KIND_MARKER},
    {"MSPTI_ACTIVITY_KIND_KERNEL", MSPTI_ACTIVITY_KIND_KERNEL},
    {"MSPTI_ACTIVITY_KIND_API", MSPTI_ACTIVITY_KIND_API},
    {"MSPTI_ACTIVITY_KIND_HCCL", MSPTI_ACTIVITY_KIND_HCCL},
    {"MSPTI_ACTIVITY_KIND_MEMORY", MSPTI_ACTIVITY_KIND_MEMORY},
    {"MSPTI_ACTIVITY_KIND_MEMSET", MSPTI_ACTIVITY_KIND_MEMSET},
    {"MSPTI_ACTIVITY_KIND_MEMCPY", MSPTI_ACTIVITY_KIND_MEMCPY},
    {"MSPTI_ACTIVITY_KIND_EXTERNAL_CORRELATION", MSPTI_ACTIVITY_KIND_EXTERNAL_CORRELATION},
};

using namespace systrace::util;

inline uint8_t *align_buffer(uint8_t *buffer, size_t align)
{
    return reinterpret_cast<uint8_t *>(
        (reinterpret_cast<uintptr_t>(buffer) + (align - 1)) & ~(align - 1));
}

bool MSPTITracker::isActivityEnabled(msptiActivityKind kind) {
    std::lock_guard<std::mutex> lock(mtx);
    return tracking_enabled.load() && enabled_activities.count(kind) > 0;
}

MSPTITracker::MSPTITracker()
{
    std::cout << "Logging initialized from preloaded library. [MSPTI_ACTIVITY_KIND_EXTERNAL_CORRELATION]" << std::endl;
    std::string file_name = "hccl_activity-" + systrace::util::GetPrimaryIP() + "-.csv";
    hcclFileWriter = std::make_unique<MSPTIHcclFileWriter>(file_name);

    startConfigMonitor();
    
    parseConfigFromFile();
    updateTrackingState();
    
    msptiSubscribe(&subscriber, nullptr, nullptr);
    msptiActivityRegisterCallbacks(UserBufferRequest, UserBufferComplete);
}

MSPTITracker::~MSPTITracker()
{
    stopConfigMonitor();
    msptiActivityFlushAll(1);
    for (const auto& pair : activity_map) {
        msptiActivityDisable(pair.second);
    }
    finish();
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

void MSPTITracker::startConfigMonitor() {
    if (!stop_config_monitor.load()) {
        config_monitor_thread = std::thread(&MSPTITracker::configMonitorThread);
        std::cout << "[MSPTI] Config monitor started, watching: " << CONFIG_FILE << std::endl;
    }
}

void MSPTITracker::stopConfigMonitor() {
    stop_config_monitor = true;
    if (config_monitor_thread.joinable()) {
        config_monitor_thread.join();
        std::cout << "[MSPTI] Config monitor stopped" << std::endl;
    }
}

void MSPTITracker::configMonitorThread() {
    time_t last_mtime = 0;
    
    while (!stop_config_monitor.load()) {
        struct stat file_stat;
        if (stat(CONFIG_FILE.c_str(), &file_stat) == 0) {
            if (file_stat.st_mtime != last_mtime) {
                std::cout << "[MSPTI] Config file changed, reloading..." << std::endl;
                parseConfigFromFile();
                updateTrackingState();
                last_mtime = file_stat.st_mtime;
            }
        } else {
            if (tracking_enabled.load()) {
                std::cout << "[MSPTI] Config file not found, disabling tracking" << std::endl;
                parseConfigFromFile();
                updateTrackingState();
                last_mtime = 0;
            }
        }
        
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

void MSPTITracker::parseConfigFromFile() {
    std::lock_guard<std::mutex> lock(mtx);
    enabled_activities.clear();
    
    std::ifstream file(CONFIG_FILE);
    if (!file.is_open()) {
        tracking_enabled = false;
        return;
    }
    
    std::string config_str;
    std::getline(file, config_str);
    file.close();
    
    if (config_str.empty()) {
        tracking_enabled = false;
        std::cout << "[MSPTI] Empty config, tracking disabled" << std::endl;
        return;
    }
    
    if (config_str == "ALL") {
        for (const auto& pair : activity_map) {
            enabled_activities.insert(pair.second);
        }
        tracking_enabled = true;
        std::cout << "[MSPTI] Tracking all activities enabled" << std::endl;
        return;
    }
    
    if (config_str == "OFF") {
        tracking_enabled = false;
        std::cout << "[MSPTI] Tracking disabled via config" << std::endl;
        return;
    }
    
    std::vector<std::string> tokens = splitConfigString(config_str);
    bool has_valid_config = false;
    
    for (const auto& token : tokens) {
        auto it = activity_map.find(token);
        if (it != activity_map.end()) {
            enabled_activities.insert(it->second);
            has_valid_config = true;
        } else {
            std::cerr << "[MSPTI] Invalid activity name: " << token << std::endl;
        }
    }
    
    tracking_enabled = has_valid_config;
    
    if (tracking_enabled) {
        std::cout << "[MSPTI] Tracking enabled for: ";
        for (msptiActivityKind kind : enabled_activities) {
            for (const auto& pair : activity_map) {
                if (pair.second == kind) {
                    std::cout << pair.first << " ";
                    break;
                }
            }
        }
        std::cout << std::endl;
    } else if (!config_str.empty() && config_str != "OFF") {
        std::cerr << "[MSPTI] No valid activities in config, tracking disabled" << std::endl;
    }
}

std::vector<std::string> MSPTITracker::splitConfigString(const std::string& str) {
    std::vector<std::string> tokens;
    std::stringstream ss(str);
    std::string token;
    
    while (std::getline(ss, token, ',')) {
        token.erase(0, token.find_first_not_of(" \t"));
        token.erase(token.find_last_not_of(" \t") + 1);
        
        if (!token.empty()) {
            tokens.push_back(token);
        }
    }
    
    return tokens;
}

void MSPTITracker::updateTrackingState() {
    std::lock_guard<std::mutex> lock(mtx);
    
    if (!tracking_enabled.load()) {
        for (const auto& pair : activity_map) {
            msptiActivityDisable(pair.second);
        }
        std::cout << "[MSPTI] All activities disabled" << std::endl;
    } else {
        for (const auto& pair : activity_map) {
            msptiActivityDisable(pair.second);
        }
        
        for (msptiActivityKind kind : enabled_activities) {
            msptiActivityEnable(kind);
        }
        
        std::cout << "[MSPTI] Enabled " << enabled_activities.size() << " activities" << std::endl;
    }
}

void MSPTITracker::UserBufferRequest(uint8_t **buffer, size_t *size,
                                     size_t *maxNumRecords)
{
    auto &instance = getInstance();
    
    if (!instance.isTrackingEnabled()) {
        *buffer = nullptr;
        *size = 0;
        *maxNumRecords = 0;
        return;
    }
    
    std::lock_guard<std::mutex> lock(mtx);
    constexpr uint32_t SIZE = (uint32_t)MB * 1;
    instance.requestedCount.fetch_add(1);
    uint8_t *pBuffer = (uint8_t *)malloc(SIZE + ALIGN_SIZE);
    if (pBuffer) {
        *buffer = align_buffer(pBuffer, ALIGN_SIZE);
        *size = MB * 1;
        *maxNumRecords = 0;
    } else {
        *buffer = nullptr;
        *size = 0;
        *maxNumRecords = 0;
    }
}

static void ShowApiInfo(msptiActivityApi* api)
{
    if(!api) {
        return;
    }
    LOG_PRINT("Api+++ kind: %d, name: %s, start: %lu, end: %lu, processId: %u, threadId: %u, correlationId: %lu\n",
            api->kind, api->name, api->start, api->end, api->pt.processId, api->pt.threadId, api->correlationId);
}

static void ShowKernelInfo(msptiActivityKernel* kernel)
{
    if(!kernel) {
        return;
    }
    LOG_PRINT("Kernel--- kind: %d, type: %s, name: %s, start: %lu, end: %lu, deviceId: %u, streamId: %u, correlationId: %lu\n",
            kernel->kind, kernel->type, kernel->name, kernel->start, kernel->end, kernel->ds.deviceId, kernel->ds.streamId, kernel->correlationId);
}

static void ShowHcclInfo(msptiActivityHccl* hccl)
{
    if(!hccl) {
        return;
    }
    LOG_PRINT("Hccl--- kind: %d, name: %s, commName: %s, start: %lu, end: %lu, deviceId: %u, streamId: %u, bandwidth: %f GB/s\n",
            hccl->kind, hccl->name, hccl->commName, hccl->start, hccl->end, 
            hccl->ds.deviceId, hccl->ds.streamId, hccl->bandWidth);
}

static void ShowMarkerInfo(msptiActivityMarker* marker)
{
    if(!marker) {
        return;
    }
    uint32_t id_val = marker->id;
    LOG_PRINT("Marker+++ kind: %d, flag: %lu, sourceKind: %d, timestamp: %lu, id: %lu, objectKind: %d, name: %s, domain: %s\n",
            marker->kind, marker->flag, marker->sourceKind, marker->timestamp, 
            marker->id, (marker->objectId.pt.processId == 0xFFFFFFFF ? 1 : 0), 
            marker->name ? marker->name : "NULL", marker->domain ? marker->domain : "NULL");
}

static void ShowMemoryInfo(msptiActivityMemory* memory)
{
    if(!memory) {
        return;
    }
    LOG_PRINT("Memory--- kind: %d, operationType: %d, memoryKind: %d, start: %lu, end: %lu, "
              "address: 0x%lx, bytes: %lu, processId: %u, deviceId: %u, streamId: %u, correlationId: %lu\n",
            memory->kind, memory->memoryOperationType, memory->memoryKind, memory->start, memory->end,
            memory->address, memory->bytes, memory->processId, memory->deviceId, memory->streamId, memory->correlationId);
}

static void ShowMemsetInfo(msptiActivityMemset* memset)
{
    if(!memset) {
        return;
    }
    LOG_PRINT("Memset--- kind: %d, value: %u, bytes: %lu, start: %lu, end: %lu, "
              "deviceId: %u, streamId: %u, correlationId: %lu, isAsync: %u\n",
            memset->kind, memset->value, memset->bytes, memset->start, memset->end,
            memset->deviceId, memset->streamId, memset->correlationId, memset->isAsync);
}

static void ShowMemcpyInfo(msptiActivityMemcpy* memcpy)
{
    if(!memcpy) {
        return;
    }
    LOG_PRINT("Memcpy--- kind: %d, copyKind: %d, bytes: %lu, start: %lu, end: %lu, "
              "deviceId: %u, streamId: %u, correlationId: %lu, isAsync: %u\n",
            memcpy->kind, memcpy->copyKind, memcpy->bytes, memcpy->start, memcpy->end,
            memcpy->deviceId, memcpy->streamId, memcpy->correlationId, memcpy->isAsync);
}

static void ShowExternalCorrelationInfo(msptiActivityExternalCorrelation* external)
{
    if(!external) {
        return;
    }
    LOG_PRINT("ExternalCorrelation--- kind: %d, externalKind: %d, externalId: %lu, correlationId: %lu\n",
            external->kind, external->externalKind, external->externalId, external->correlationId);
}

void MSPTITracker::UserBufferComplete(uint8_t *buffer, size_t size,
                                      size_t validSize)
{
    if (validSize > 0 && buffer != nullptr) {
        msptiActivity *pRecord = NULL;
        msptiResult status = MSPTI_SUCCESS;
        
        auto& instance = getInstance();
        
        do {
            status = msptiActivityGetNextRecord(buffer, validSize, &pRecord);
            if (status == MSPTI_SUCCESS) {
                if (!instance.isTrackingEnabled() || 
                    !instance.isActivityEnabled(pRecord->kind)) {
                    continue;
                }
                
                if (pRecord->kind == MSPTI_ACTIVITY_KIND_MARKER) {
                    msptiActivityMarker* activity = reinterpret_cast<msptiActivityMarker*>(pRecord);
                    ShowMarkerInfo(activity);
                } else if (pRecord->kind == MSPTI_ACTIVITY_KIND_KERNEL) {
                    msptiActivityKernel* activity = reinterpret_cast<msptiActivityKernel*>(pRecord);
                    ShowKernelInfo(activity);
                } else if (pRecord->kind == MSPTI_ACTIVITY_KIND_API) {
                    msptiActivityApi* activity = reinterpret_cast<msptiActivityApi*>(pRecord);
                    ShowApiInfo(activity);
                } else if (pRecord->kind == MSPTI_ACTIVITY_KIND_HCCL) {
                    msptiActivityHccl* activity = reinterpret_cast<msptiActivityHccl*>(pRecord);
                    ShowHcclInfo(activity);
                } else if (pRecord->kind == MSPTI_ACTIVITY_KIND_MEMORY) {
                    msptiActivityMemory* activity = reinterpret_cast<msptiActivityMemory*>(pRecord);
                    ShowMemoryInfo(activity);
                } else if (pRecord->kind == MSPTI_ACTIVITY_KIND_MEMSET) {
                    msptiActivityMemset* activity = reinterpret_cast<msptiActivityMemset*>(pRecord);
                    ShowMemsetInfo(activity);
                } else if (pRecord->kind == MSPTI_ACTIVITY_KIND_MEMCPY) {
                    msptiActivityMemcpy* activity = reinterpret_cast<msptiActivityMemcpy*>(pRecord);
                    ShowMemcpyInfo(activity);
                } else if (pRecord->kind == MSPTI_ACTIVITY_KIND_EXTERNAL_CORRELATION) {
                    msptiActivityExternalCorrelation* activity = reinterpret_cast<msptiActivityExternalCorrelation*>(pRecord);
                    ShowExternalCorrelationInfo(activity);
                } else {
                    LOG_PRINT("Unknown activity kind: %d\n", pRecord->kind);
                }
            } else if (status == MSPTI_ERROR_MAX_LIMIT_REACHED) {
                break;
            } else {
                break;
            }
        } while (status == MSPTI_SUCCESS);
    }
    
    if (buffer) {
        free(buffer);
    }
}