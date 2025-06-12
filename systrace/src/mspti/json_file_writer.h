#pragma once
#include "../../include/common/shared_constants.h"
#include "../../include/common/util.h"
#include "mspti.h"
#include <atomic>
#include <condition_variable>
#include <fstream>
#include <iostream>
#include <json/json.h>
#include <mutex>
#include <string.h>
#include <thread>
#include <vector>

class MSPTIHcclFileWriter
{
  private:
    std::ofstream file;
    std::mutex buffermtx;
    std::mutex bufferMarkerMtx;
    std::mutex threadmtx;
    std::atomic<bool> opened;
    std::unique_ptr<std::vector<msptiActivityMarker>> markerActivityBuffer;
    std::thread writerThread;
    std::condition_variable cv;
    std::atomic<bool> stop;
    Json::Value root = Json::Value(Json::ValueType::arrayValue);

  public:
    MSPTIHcclFileWriter(const std::string &filename)
    {
        // obtain environment variable LOCAL_RANK
        // to determine the rank of the process
        // and append it to the filename
        const char *path = std::getenv("METRIC_PATH");
        std::string savePath = path ? path : SYS_TRACE_ROOT_DIR "mspti/";
        if (systrace::util::fs_utils::CreateDirectoryIfNotExists(savePath))
        {
            STLOG(ERROR) << "[MSPTI] Failed to create dump directory";
            return;
        }
        std::string savePathStr = savePath;
        if (!savePathStr.empty() && savePathStr.back() != '/')
        {
            savePathStr += "/";
        }
        std::string saveFilename = savePathStr + filename;
        std::string filenameWithRank = saveFilename;
        this->markerActivityBuffer =
            std::make_unique<std::vector<msptiActivityMarker>>();

        const char *localRankCStr = std::getenv("RANK");
        if (localRankCStr == nullptr)
        {
            localRankCStr = "-1";
        }
        std::string localRank =
            localRankCStr; // Now safe to construct std::string
        auto rank = std::stoi(localRank);
        if (saveFilename.length() >= 5 &&
            saveFilename.substr(saveFilename.length() - 5) == ".json")
        {
            std::string baseName =
                saveFilename.substr(0, saveFilename.length() - 5);
            filenameWithRank = baseName + "." + std::to_string(rank) + ".json";
        }
        else
        {
            filenameWithRank = saveFilename + "." + std::to_string(rank);
        }
        std::cout << "Filename: " << filenameWithRank << std::endl;
        this->file.open(filenameWithRank, std::ios::out | std::ios::app);
        this->opened.store(true);
        this->stop.store(false);
        this->run();
    }

    void stopWriter()
    {
        if (this->file.is_open())
        {
            {
                std::unique_lock<std::mutex> lock(this->threadmtx);
                this->stop.store(true);
            }
            this->cv.notify_all();
            this->hcclActivityFormatToJson();
            if (this->writerThread.joinable())
            {
                this->writerThread.join();
            }
            this->file.close();
            this->opened.store(false);
        }
    }

    ~MSPTIHcclFileWriter() { this->stopWriter(); }

    bool fileExists(const std::string &fp)
    {
        std::ifstream file(fp.c_str());
        return file.good() && file.is_open();
    }

    void bufferMarkerActivity(msptiActivityMarker *activity)
    {
        std::lock_guard<std::mutex> lock(this->bufferMarkerMtx);
        this->markerActivityBuffer->push_back(*activity);
    }

    void run()
    {
        // a thread to periodically flush
        // the buffer to the file
        // watch the conditional variable for signal
        this->writerThread = std::thread(
            [this]()
            {
                while (!this->stop.load())
                {
                    std::unique_lock<std::mutex> lock(this->threadmtx);
                    if (this->cv.wait_for(lock, std::chrono::seconds(5)) ==
                        std::cv_status::timeout)
                    {
                        this->hcclActivityFormatToJson();
                    }
                    else if (this->stop.load())
                    {
                        break;
                    };
                }
            });
    }

    void hcclActivityFormatToJson()
    {
        std::lock_guard<std::mutex> lock(this->buffermtx);
        if (this->file.is_open())
        {
            for (auto activity : *this->markerActivityBuffer)
            {
                Json::Value markerJson;
                markerJson["Kind"] = activity.kind;
                markerJson["SourceKind"] = activity.sourceKind;
                markerJson["Timestamp"] = activity.timestamp;
                markerJson["Id"] = activity.id;
                markerJson["Flag"] = activity.flag;
                Json::Value msptiObjecId;
                if (activity.sourceKind == MSPTI_ACTIVITY_SOURCE_KIND_HOST)
                {
                    Json::Value pt;
                    pt["ProcessId"] = activity.objectId.pt.processId;
                    pt["ThreadId"] = activity.objectId.pt.threadId;
                    Json::Value ds;
                    ds["DeviceId"] = activity.objectId.pt.processId;
                    ds["StreamId"] = activity.objectId.pt.threadId;
                    msptiObjecId["Pt"] = pt;
                    msptiObjecId["Ds"] = ds;
                }
                else if (activity.sourceKind ==
                         MSPTI_ACTIVITY_SOURCE_KIND_DEVICE)
                {
                    Json::Value ds;
                    ds["DeviceId"] = activity.objectId.ds.deviceId;
                    ds["StreamId"] = activity.objectId.ds.streamId;
                    Json::Value pt;
                    pt["ProcessId"] = activity.objectId.ds.deviceId;
                    pt["ThreadId"] = activity.objectId.ds.streamId;
                    msptiObjecId["Pt"] = pt;
                    msptiObjecId["Ds"] = ds;
                }
                markerJson["msptiObjectId"] = msptiObjecId;
                markerJson["Name"] = activity.name;
                this->root.append(markerJson);
            }
            if (this->root.size() > 0)
            {
                Json::StyledWriter writer;
                this->file << writer.write(this->root);
                this->root.clear();
            }
            this->markerActivityBuffer->clear();
        }
        else
        {
            std::cout << "File is not open" << std::endl;
        }
    }
};