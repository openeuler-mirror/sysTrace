
def _demangle_msvc(name: str) -> str:
    import ctypes
    from ctypes import wintypes
    assert isinstance(name, str)

    dbghelp = ctypes.WinDLL("dbghelp")

    UnDecorateSymbolName = dbghelp.UnDecorateSymbolName
    UnDecorateSymbolName.argtypes = [
        wintypes.LPCSTR,
        wintypes.LPSTR,
        wintypes.DWORD,
        wintypes.DWORD
    ]
    UnDecorateSymbolName.restype = wintypes.DWORD

    UNDNAME_COMPLETE = 0x0000
    buffer = ctypes.create_string_buffer(4096)
    res = UnDecorateSymbolName(
        name.encode("utf-8"),
        buffer,
        ctypes.sizeof(buffer),
        UNDNAME_COMPLETE
    )
    return buffer.value.decode("utf-8") if res else name

def _demangle_nccl_kernel(symbol: str) -> str:
    if not symbol.startswith("_Z"):
        return None

    s = symbol[2:]  # 去掉 _Z

    # 解析长度
    i = 0
    while i < len(s) and s[i].isdigit():
        i += 1

    if i == 0:
        return symbol

    length = int(s[:i])
    name = s[i:i + length]
    return name


_demangle_funcs = [
    _demangle_nccl_kernel
]

# FIXME：尝试添加cxxfilt
'''
try:
    from cxxfilt import demangle as cxxfilt_demangle
    cxxfilt_demangle("_Z39ncclDevKernel_AllReduce_Sum_f32_RING_LL24ncclDevKernelArgsStorageILm4096EE")
    _demangle_funcs.append(cxxfilt_demangle)
except Exception:
    pass
'''

# 尝试添加msvc demangle
try:
    _demangle_msvc("??0?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QEAA@XZ")
    _demangle_funcs.append(_demangle_msvc)
except Exception:
    pass



def demangle(name: str) -> str:
    for func in _demangle_funcs:
        demangle_name = func(name)
        if demangle_name is not None:
            return demangle_name
    return name





__all__ = ["demangle"]

