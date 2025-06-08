#pragma once
#include <iostream>
#include <string>
#include <unordered_map>

#include "../../../include/common/util.h"
#include "pytorch_tracing.h"
#include "pytorch_tracing_data.h"

namespace systrace
{
namespace pytorch_tracing_manager
{

class PyTorchTracingManager
{
  public:
    PyTorchTracingManager(const PyTorchTracingManager &) = delete;
    PyTorchTracingManager &operator=(const PyTorchTracingManager &) = delete;
    static void initSingleton();
    static PyTorchTracingManager &getInstance();

    PyTorchTracingDataArray *getEmptyPyTorchTracingDataArray(int name);
    void returnPyTorchTracingDataArray(PyTorchTracingDataArray *, int,
                                       int name);
    PyTorchTracingDataArray *getPyTorchTracingDataArray(int name);
    PyTorchTracingDataArray *getCurPyTorchTracingDataArray(int name);

  private:
    PyTorchTracingManager() = default;
    inline static PyTorchTracingManager *instance_ = nullptr;
    inline static std::once_flag init_flag_;
    struct Pool
    {
        util::resource::TimerPool<PyTorchTracingDataArray> empty_pool;
        util::resource::TimerPool<PyTorchTracingDataArray> ready_pool;
    };
    std::unordered_map<int, Pool> pool_;
};
} // namespace pytorch_tracing_manager
} // namespace systrace

#ifdef __cplusplus
extern "C"
{
#endif
    PyTorchTracingDataArray *
    systrace_get_empty_pytorch_tracing_data_array(int name)
    {
        return systrace::pytorch_tracing_manager::PyTorchTracingManager::
            getInstance()
                .getEmptyPyTorchTracingDataArray(name);
    }

    PyTorchTracingDataArray *
    systrace_get_full_pytorch_tracing_data_array(int name)
    {
        return systrace::pytorch_tracing_manager::PyTorchTracingManager::
            getInstance()
                .getPyTorchTracingDataArray(name);
    }

    void
    systrace_return_pytorch_tracing_data_array(PyTorchTracingDataArray *array,
                                               int type, int name)
    {
        systrace::pytorch_tracing_manager::PyTorchTracingManager::getInstance()
            .returnPyTorchTracingDataArray(array, type, name);
    }

#ifdef __cplusplus
}
#endif