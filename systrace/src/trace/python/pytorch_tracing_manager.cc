#include "pytorch_tracing_manager.h"
#include "pytorch_tracing_data.h"
#include <cstring>
#include <thread>

namespace systrace
{
namespace pytorch_tracing_manager
{

PyTorchTracingManager &PyTorchTracingManager::getInstance()
{
    std::call_once(init_flag_, &PyTorchTracingManager::initSingleton);
    return *instance_;
}

void PyTorchTracingManager::initSingleton()
{
    instance_ = new PyTorchTracingManager();
}

PyTorchTracingDataArray *
PyTorchTracingManager::getEmptyPyTorchTracingDataArray(int name)
{
    auto &pool_item = pool_[name];
    auto *data = pool_item.empty_pool.getObject();
    std::memset(data, 0, sizeof(PyTorchTracingDataArray));
    return data;
}

void PyTorchTracingManager::returnPyTorchTracingDataArray(
    PyTorchTracingDataArray *array, int type, int name)
{

    if (!array)
        return;

    auto &pool_item = pool_[name];
    int pool_queue_size = 0;

    switch (type)
    {
    case PY_TRACING_READY_POOL:
        pool_item.ready_pool.returnObject(array, &pool_queue_size);
        break;
    case PY_TRACING_EMPTY_POOL:
        pool_item.empty_pool.returnObject(array, &pool_queue_size);
        break;
    }
}

PyTorchTracingDataArray *
PyTorchTracingManager::getPyTorchTracingDataArray(int name)
{
    return pool_[name].ready_pool.getObject<false>();
}
} // namespace pytorch_tracing_manager
} // namespace systrace