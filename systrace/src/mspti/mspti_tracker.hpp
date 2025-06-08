#include "json_file_writer.h"
#include "mspti.h"
#include <atomic>
#include <memory>
#include <mutex>

class MSPTITracker
{
  private:
    static std::mutex mtx;

    msptiSubscriberHandle subscriber;
    std::unique_ptr<MSPTIHcclFileWriter> hcclFileWriter;
    std::atomic<int> requestedCount{0};

    MSPTITracker();
    ~MSPTITracker();

  public:
    MSPTITracker(const MSPTITracker &) = delete;
    MSPTITracker &operator=(const MSPTITracker &) = delete;

    static MSPTITracker &getInstance();

    msptiSubscriberHandle *getSubscriber() { return &subscriber; }
    void finish();
    void readActivityMarker(msptiActivityMarker *activity);

    static void UserBufferRequest(uint8_t **buffer, size_t *size,
                                  size_t *maxNumRecords);
    static void UserBufferComplete(uint8_t *buffer, size_t size,
                                   size_t validSize);
};