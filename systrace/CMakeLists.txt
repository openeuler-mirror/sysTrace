cmake_minimum_required(VERSION 3.10)
project(sysTrace)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_SKIP_RPATH TRUE)
set(CMAKE_BUILD_WITH_INSTALL_RPATH FALSE)
set(CMAKE_INSTALL_RPATH "")
set(CMAKE_INSTALL_RPATH_USE_LINK_PATH FALSE)
option(USE_JSON_FORMAT "Build with JSON output and NO protobuf link" OFF)
option(HAS_BTF_SUPPORT "Enable BPF modules with BTF support" OFF)
option(ENABLE_PYTHON_TRACING "Enable Python-based tracing (links libpython)" ON)

if(USE_JSON_FORMAT)
    add_definitions(-DUSE_JSON)
    message(STATUS ">>> Build Mode: JSON (Protobuf linking disabled) <<<")
else()
    message(STATUS ">>> Build Mode: Protobuf (Binary format) <<<")
endif()

if(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|ARM64")
    set(UNWIND_LIB "unwind-aarch64")
    set(MSPTI_INCLUDE "${PROJECT_SOURCE_DIR}/thirdparty/aarch64/mspti/include")
    set(MSPTI_LIB "${PROJECT_SOURCE_DIR}/thirdparty/aarch64/mspti/lib64")
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64")
    find_library(
        UNWIND_LIB
        NAMES libunwind-x86_64.so.8
        PATHS /usr
    )
    set(MSPTI_INCLUDE "${PROJECT_SOURCE_DIR}/thirdparty/x86_64/mspti/include")
    set(MSPTI_LIB "${PROJECT_SOURCE_DIR}/thirdparty/x86_64/mspti/lib64")
else()
    message(WARNING "Unknown architecture: ${CMAKE_SYSTEM_PROCESSOR}")
    set(UNWIND_LIB "unwind")
endif()
include_directories(
    ${MSPTI_INCLUDE}
)

if(ENABLE_PYTHON_TRACING)
    message(STATUS ">>> Python tracing: ENABLED (will link libpython) <<<")
    find_package(Python3 REQUIRED COMPONENTS Development)
else()
    message(STATUS ">>> Python tracing: DISABLED (no libpython link) <<<")
endif()
find_package(Threads REQUIRED)

if(NOT USE_JSON_FORMAT)
    find_package(Protobuf REQUIRED)
endif()
add_library(common STATIC
    ${PROJECT_SOURCE_DIR}/include/log/logging.cc
    ${PROJECT_SOURCE_DIR}/include/common/constant.c
    ${PROJECT_SOURCE_DIR}/include/utils/util.cc
    ${PROJECT_SOURCE_DIR}/include/utils/TimerManager.hpp
)
target_include_directories(common PUBLIC
    ${PROJECT_SOURCE_DIR}/include
)

if(ENABLE_PYTHON_TRACING)
    target_include_directories(common PUBLIC
        ${Python3_INCLUDE_DIRS}
    )
endif()


if(NOT USE_JSON_FORMAT)
    add_subdirectory(protos)
    set(PB_SOURCES "${PROJECT_SOURCE_DIR}/protos/systrace.pb-c.c")
    set(PB_LIBS protobuf::libprotobuf protobuf-c general_pb2)
else()
    set(PB_SOURCES "")
    set(PB_LIBS "")
endif()

if(HAS_BTF_SUPPORT)
    message(STATUS "Enabling BPF modules with BTF support")
    add_subdirectory(src/os)
endif()

set(SYSTRACE_SOURCES
    ${PROJECT_SOURCE_DIR}/src/trace/systrace_manager.cc
    ${PROJECT_SOURCE_DIR}/src/trace/library_loader.cc
    ${PROJECT_SOURCE_DIR}/src/trace/python/pytorch_tracing_loader.cc
    ${PROJECT_SOURCE_DIR}/src/trace/python/pytorch_tracing_manager.cc
    ${PROJECT_SOURCE_DIR}/src/ascend/hook.cc
    ${PROJECT_SOURCE_DIR}/src/mspti/mspti_tracker.cpp
    ${PROJECT_SOURCE_DIR}/src/cann/common_hook.c
    ${PROJECT_SOURCE_DIR}/src/cann/mem_hook.c
    ${PROJECT_SOURCE_DIR}/src/cann/io_hook.c
    ${PROJECT_SOURCE_DIR}/src/plugins/manager/ControlManager.cpp
    ${PROJECT_SOURCE_DIR}/src/plugins/HbmPlugin.hpp
    ${PROJECT_SOURCE_DIR}/src/plugins/ebpfPluginBase/EbpfCollectorBase.cpp
    ${PROJECT_SOURCE_DIR}/src/plugins/ftrace/FtracePlugin.cpp
)

if(ENABLE_PYTHON_TRACING)
    list(APPEND SYSTRACE_SOURCES
        ${PROJECT_SOURCE_DIR}/src/trace/python/pytorch_tracing.c
    )
endif()

if(HAS_BPF_SUPPORT)
    message(STATUS "Enabling BPF modules")
    list(APPEND SYSTRACE_SOURCES
        ${PROJECT_SOURCE_DIR}/src/plugins/gil/GilPlugin.cpp
        ${PROJECT_SOURCE_DIR}/src/plugins/pthread/PthreadPlugin.cpp
    )
    add_subdirectory(src/plugins/ebpf)
else()
    message(WARNING "Disabling BPF modules")
endif()

add_library(sysTrace_hook SHARED ${SYSTRACE_SOURCES})

add_executable(sysTrace_cli
    ${PROJECT_SOURCE_DIR}/client/sysTracecli.cpp
)
set_target_properties(sysTrace_hook PROPERTIES OUTPUT_NAME "sysTrace")

if(HAS_BTF_SUPPORT)
    target_compile_definitions(sysTrace_hook PRIVATE HAS_BTF_SUPPORT=1)
endif()

if(HAS_BPF_SUPPORT)
    target_compile_definitions(sysTrace_hook PRIVATE HAS_BPF_SUPPORT=1)
endif()

if(ENABLE_PYTHON_TRACING)
    target_compile_definitions(sysTrace_hook PRIVATE ENABLE_PYTHON_TRACING=1)
endif()

target_link_libraries(sysTrace_hook
    common
    ${PB_LIBS}
    ${CMAKE_THREAD_LIBS}
    pthread
    -ldl
)

if(ENABLE_PYTHON_TRACING)
    target_link_libraries(sysTrace_hook
        ${Python3_LIBRARIES}
    )
endif()

if(HAS_BTF_SUPPORT)
    target_link_libraries(sysTrace_hook os_probe)
endif()

if(NOT USE_JSON_FORMAT)
    target_link_libraries(sysTrace_cli general_pb2)
endif()

if(HAS_BPF_SUPPORT)
    target_link_libraries(sysTrace_hook ebpf_module)
    message(STATUS "Linking ebpf_module library")
endif()

target_link_libraries(sysTrace_hook
    ${UNWIND_LIB}
)
