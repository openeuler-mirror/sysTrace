#pragma once

#include "../../include/common/util.h"
#include <map>
#include <string>
#include <string_view>
#include <vector>

namespace systrace
{

class DynamicLibraryLoader
{
  protected:
    void *library_handle_;
    bool is_usable_;
    const std::string library_path_;

    void LoadDynamicLibrary();

  public:
    explicit DynamicLibraryLoader(const std::string &library_path);
    virtual ~DynamicLibraryLoader();

    bool IsLibraryLoaded() const
    {
        return library_handle_ != nullptr && is_usable_;
    }
    void *GetLibraryHandle() const { return library_handle_; }
};

} // namespace systrace