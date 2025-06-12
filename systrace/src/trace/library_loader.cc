#include "library_loader.h"
#include "../../include/common/logging.h"
#include <dlfcn.h>

namespace systrace
{

DynamicLibraryLoader::DynamicLibraryLoader(const std::string &library_path)
    : library_handle_(nullptr), is_usable_(false), library_path_(library_path)
{
    LoadDynamicLibrary();
}

DynamicLibraryLoader::~DynamicLibraryLoader()
{
    if (library_handle_)
    {
        dlclose(library_handle_);
        library_handle_ = nullptr;
    }
}

void DynamicLibraryLoader::LoadDynamicLibrary()
{
    if (library_handle_)
    {
        STLOG(WARNING) << "Library already loaded: " << library_path_;
        return;
    }

    dlerror();

    library_handle_ = dlopen(library_path_.c_str(), RTLD_LAZY);
    if (!library_handle_)
    {
        const char *error_message = dlerror();
        STLOG(WARNING) << "Failed to load library: "
                       << (error_message ? error_message : "Unknown error");
        is_usable_ = false;
        return;
    }

    is_usable_ = true;
}

} // namespace systrace