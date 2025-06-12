#include "pytorch_tracing_loader.h"
#include "../../../include/common/logging.h"
#include <cstring>
#include <dlfcn.h>

namespace systrace
{
namespace pytorch_tracing
{

PyTorchTracingLibrary::PyTorchTracingLibrary(const std::string &library_path)
    : DynamicLibraryLoader(library_path), register_tracing_(nullptr),
      get_tracing_data_(nullptr), get_partial_tracing_data_(nullptr),
      return_tracing_data_(nullptr)
{
    if (library_handle_)
    {
        InitializeSymbols();
    }
}

void PyTorchTracingLibrary::InitializeSymbols()
{
    std::vector<SymbolConfig> configs = {
        {"systrace_register_tracing",
         [this]() { return reinterpret_cast<void *>(&register_tracing_); },
         "TracingRegistrationFunc"},

        {"systrace_get_full_pytorch_tracing_data_array",
         [this]() { return reinterpret_cast<void *>(&get_tracing_data_); },
         "DataArrayRetrievalAllFunc"},

        {"systrace_return_pytorch_tracing_data_array",
         [this]() { return reinterpret_cast<void *>(&return_tracing_data_); },
         "DataArrayReleaseFunc"},

        {"systrace_get_partial_pytorch_tracing_data_array", [this]()
         { return reinterpret_cast<void *>(&get_partial_tracing_data_); },
         "GetPartialTracingDataArrayPartFunc"}};

    is_usable_ = std::all_of(configs.begin(), configs.end(),
                             [this](const SymbolConfig &config)
                             { return LoadSymbol(config); });
}

bool PyTorchTracingLibrary::LoadSymbol(const SymbolConfig &config)
{
    void *symbol = dlsym(library_handle_, config.name);
    if (!symbol)
    {
        STLOG(WARNING) << "Failed to load symbol: " << config.name
                       << " (type: " << config.type_name
                       << "), error: " << dlerror();
        return false;
    }

    *reinterpret_cast<void **>(config.loader()) = symbol;
    return true;
}

std::vector<std::string>
PyTorchTracingLibrary::Register(const std::vector<std::string> &names)
{
    if (!is_usable_)
    {
        return {};
    }

    auto error_holder = std::unique_ptr<char *[], std::function<void(char **)>>(
        new char *[names.size()],
        [size = names.size()](char **ptr)
        {
            for (size_t i = 0; i < size; ++i)
            {
                free(ptr[i]);
            }
            delete[] ptr;
        });
    std::memset(error_holder.get(), 0, names.size() * sizeof(char *));

    std::vector<const char *> c_str_array;
    c_str_array.reserve(names.size());
    std::transform(names.begin(), names.end(), std::back_inserter(c_str_array),
                   [](const std::string &str) { return str.c_str(); });

    register_tracing_(c_str_array.data(), c_str_array.size(),
                      error_holder.get());

    std::vector<std::string> result;
    for (size_t i = 0; i < names.size(); ++i)
    {
        if (error_holder[i])
        {
            result.emplace_back(error_holder[i]);
        }
    }
    return result;
}

PyTorchTracingDataArray *PyTorchTracingLibrary::RetrieveAllTracingData(int name)
{
    return is_usable_ ? get_tracing_data_(name) : nullptr;
}

PyTorchTracingDataArray *
PyTorchTracingLibrary::RetrievePartialTracingData(int name)
{
    return is_usable_ ? get_partial_tracing_data_(name) : nullptr;
}

void PyTorchTracingLibrary::ReleaseTracingData(PyTorchTracingDataArray *data,
                                               int type, int name)
{
    if (is_usable_ && data)
    {
        return_tracing_data_(data, type, name);
    }
}

} // namespace pytorch_tracing
} // namespace systrace