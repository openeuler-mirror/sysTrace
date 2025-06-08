#pragma once

#include <string>
#include <vector>

#include "../../../include/common/macro.h"
#include "../library_loader.h"
#include "pytorch_tracing_data.h"

namespace systrace
{
namespace pytorch_tracing
{

class PyTorchTracingLibrary : public DynamicLibraryLoader
{
  public:
    explicit PyTorchTracingLibrary(const std::string &);
    using TracingRegistrationFunc = void (*)(const char **, int, char **);
    using DataArrayRetrievalAllFunc = PyTorchTracingDataArray *(*)(int);
    using GetPartialTracingDataArrayPartFunc =
        PyTorchTracingDataArray *(*)(int);
    using DataArrayReleaseFunc = void (*)(PyTorchTracingDataArray *, int, int);
    PyTorchTracingDataArray *RetrieveAllTracingData(int);
    PyTorchTracingDataArray *RetrievePartialTracingData(int);
    std::vector<std::string> Register(const std::vector<std::string> &names);
    void ReleaseTracingData(PyTorchTracingDataArray *data, int type, int name);

  private:
    TracingRegistrationFunc register_tracing_;
    DataArrayRetrievalAllFunc get_tracing_data_;
    GetPartialTracingDataArrayPartFunc get_partial_tracing_data_;
    DataArrayReleaseFunc return_tracing_data_;
    void InitializeSymbols();
    struct SymbolConfig
    {
        const char *name;
        std::function<void *(void)> loader;
        const char *type_name;
    };
    bool LoadSymbol(const SymbolConfig &config);
};

} // namespace pytorch_tracing
} // namespace systrace