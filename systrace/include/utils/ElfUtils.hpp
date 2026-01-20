#pragma once

#include <cstdio>
#include <cstring>
#include <elfutils/libdwfl.h>
#include <fcntl.h>
#include <gelf.h>
#include <iostream>
#include <string>
#include <unistd.h>

namespace systrace {
namespace elfutils {

class ElfUtils {
  public:
    static inline int get_so_path(int pid, char *elf_path, int size,
                                  const char *so_keyword) {
        char map_file[512];
        char buf[512];
        snprintf(map_file, sizeof(map_file), "/proc/%d/maps", pid);

        FILE *fp = fopen(map_file, "r");
        if (!fp)
            return -1;

        while (fgets(buf, sizeof(buf), fp)) {
            char so_path[512] = {0};
            if (sscanf(buf, "%*x-%*x %*s %*s %*s %*s %511s", so_path) != 1)
                continue;

            if (strstr(so_path, so_keyword)) {
                snprintf(elf_path, size, "/proc/%d/root%s", pid, so_path);
                fclose(fp);
                return 0;
            }
        }
        fclose(fp);
        return -1;
    }

    static inline unsigned long find_function_offset(const char *bin_path,
                                                     const char *func_name) {
        if (!bin_path || !func_name)
            return 0;
        int fd = open(bin_path, O_RDONLY);
        if (fd < 0)
            return 0;

        static const Dwfl_Callbacks callbacks = {
            .find_elf = dwfl_linux_proc_find_elf,
            .find_debuginfo = dwfl_standard_find_debuginfo,
        };

        Dwfl *dwfl = dwfl_begin(&callbacks);
        if (!dwfl) {
            close(fd);
            return 0;
        }

        if (dwfl_report_offline(dwfl, bin_path, bin_path, fd) == nullptr) {
            dwfl_end(dwfl);
            close(fd);
            return 0;
        }
        dwfl_report_end(dwfl, nullptr, nullptr);

        struct SearchCtx {
            const char *name;
            unsigned long offset;
        } ctx = {func_name, 0};

        auto callback = [](Dwfl_Module *mod, void **userdata, const char *name,
                           Dwarf_Addr base, void *arg) -> int {
            SearchCtx *s_ctx = static_cast<SearchCtx *>(arg);
            int nsym = dwfl_module_getsymtab(mod);
            for (int i = 0; i < nsym; ++i) {
                GElf_Sym sym;
                const char *sname = dwfl_module_getsym(mod, i, &sym, nullptr);
                if (sname && std::string(sname) == s_ctx->name) {
                    Dwarf_Addr load_addr;
                    dwfl_module_info(mod, nullptr, &load_addr, nullptr, nullptr,
                                     nullptr, nullptr, nullptr);
                    s_ctx->offset =
                        static_cast<unsigned long>(sym.st_value - load_addr);
                    return DWARF_CB_ABORT;
                }
            }
            return DWARF_CB_OK;
        };

        dwfl_getmodules(dwfl, callback, &ctx, 0);
        dwfl_end(dwfl);
        return ctx.offset;
    }
};

} // namespace elfutils
} // namespace systrace