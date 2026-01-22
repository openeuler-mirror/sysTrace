#pragma once
#include "../../include/common/constant.h"
#include "../../include/log/logging.h"
#include "../../include/utils/util.h"
#include "mspti.h"
#include <atomic>
#include <condition_variable>
#include <fstream>
#include <mutex>
#include <thread>
#include <vector>

class MSPTIHcclFileWriter {
  private:
    std::ofstream fM, fK, fA; // Marker, Kernel, Api
    std::mutex bmtx, tmtx;
    std::unique_ptr<std::vector<msptiActivityMarker>> bM;
    std::unique_ptr<std::vector<msptiActivityKernel>> bK;
    std::unique_ptr<std::vector<msptiActivityApi>> bA;
    std::thread writerThread;
    std::condition_variable cv;
    std::atomic<bool> stop;

    std::string getFn(const std::string &type, int rank) {
        const char *path = std::getenv("METRIC_PATH");
        std::string p = path ? path : SYS_TRACE_ROOT_DIR "mspti/";
        systrace::util::fs_utils::CreateDirectoryIfNotExists(p);
        if (!p.empty() && p.back() != '/')
            p += "/";
        return p + "mspti-" + type + "-" + systrace::util::GetPrimaryIP() +
               "-" + std::to_string(rank) + ".csv";
    }

    void writeRecord(std::ofstream &f, const msptiActivityMarker &a) {
        f << a.flag << "," << a.id << "," << a.kind << "," << s(a.name) << ","
          << a.sourceKind << "," << a.timestamp << ",";
        if (a.sourceKind == MSPTI_ACTIVITY_SOURCE_KIND_DEVICE) {
            f << a.objectId.ds.deviceId << "," << a.objectId.ds.streamId
              << ",,";
        } else {
            f << ",," << a.objectId.pt.processId << ","
              << a.objectId.pt.threadId;
        }
        f << "\n";
    }

    void writeRecord(std::ofstream &f, const msptiActivityKernel &a) {
        f << a.kind << "," << a.start << "," << a.end << "," << a.ds.deviceId
          << "," << a.ds.streamId << "," << a.correlationId << "," << s(a.type)
          << "," << s(a.name) << "\n";
    }

    void writeRecord(std::ofstream &f, const msptiActivityApi &a) {
        f << a.kind << "," << a.start << "," << a.end << "," << a.pt.processId
          << "," << a.pt.threadId << "," << a.correlationId << "," << s(a.name)
          << "\n";
    }

    template <typename T>
    void flushBuffer(std::ofstream &f, std::vector<T> &buffer) {
        if (!f.is_open() || buffer.empty())
            return;
        for (const auto &record : buffer) {
            writeRecord(f, record);
        }
        buffer.clear();
        f.flush();
    }

  public:
    MSPTIHcclFileWriter(const std::string &fn) {
        const char *rS =
            std::getenv("RANK")
                ? std::getenv("RANK")
                : (std::getenv("RANK_ID") ? std::getenv("RANK_ID") : "-1");
        int rank = std::stoi(rS);
        bM = std::make_unique<std::vector<msptiActivityMarker>>();
        bK = std::make_unique<std::vector<msptiActivityKernel>>();
        bA = std::make_unique<std::vector<msptiActivityApi>>();

        fM.open(getFn("marker", rank), std::ios::out | std::ios::app);
        fM << "Flag,Id,Kind,Name,SourceKind,Timestamp,msptiObjectId_Ds_"
              "DeviceId,msptiObjectId_Ds_StreamId,msptiObjectId_Pt_ProcessId,"
              "msptiObjectId_Pt_ThreadId"
           << std::endl;
        fK.open(getFn("kernel", rank), std::ios::out | std::ios::app);
        fK << "Kind,Start,End,DevId,StrmId,CorrId,Type,Name" << std::endl;
        fA.open(getFn("api", rank), std::ios::out | std::ios::app);
        fA << "Kind,Start,End,Pid,Tid,CorrId,Name" << std::endl;

        stop.store(false);
        run();
    }

    void bufferMarkerActivity(msptiActivityMarker *a) {
        std::lock_guard<std::mutex> l(bmtx);
        bM->push_back(*a);
    }
    void bufferKernelActivity(msptiActivityKernel *a) {
        std::lock_guard<std::mutex> l(bmtx);
        bK->push_back(*a);
    }
    void bufferApiActivity(msptiActivityApi *a) {
        std::lock_guard<std::mutex> l(bmtx);
        bA->push_back(*a);
    }

    void stopWriter() {
        {
            std::unique_lock<std::mutex> l(tmtx);
            stop.store(true);
        }
        cv.notify_all();
        if (writerThread.joinable())
            writerThread.join();
        flush();
        if (fM.is_open())
            fM.close();
        if (fK.is_open())
            fK.close();
        if (fA.is_open())
            fA.close();
    }

    ~MSPTIHcclFileWriter() { stopWriter(); }

    void run() {
        writerThread = std::thread([this]() {
            while (!stop.load()) {
                std::unique_lock<std::mutex> l(tmtx);
                if (cv.wait_for(l, std::chrono::seconds(5)) ==
                    std::cv_status::timeout)
                    flush();
                else if (stop.load())
                    break;
            }
        });
    }

    const char *s(const char *i) { return i ? i : "NULL"; }

    void flush() {
        std::lock_guard<std::mutex> l(bmtx);
        flushBuffer(fM, *bM);
        flushBuffer(fK, *bK);
        flushBuffer(fA, *bA);
    }
};