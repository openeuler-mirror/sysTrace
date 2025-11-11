cmake_minimum_required(VERSION 3.10)
project(sysTrace)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_SKIP_RPATH TRUE)
set(CMAKE_BUILD_WITH_INSTALL_RPATH FALSE)
set(CMAKE_INSTALL_RPATH "")
set(CMAKE_INSTALL_RPATH_USE_LINK_PATH FALSE)

find_package(Python3 REQUIRED COMPONENTS Development)
find_package(Threads REQUIRED)

add_library(common STATIC
    ${PROJECT_SOURCE_DIR}/include/common/logging.cc
    ${PROJECT_SOURCE_DIR}/include/common/util.cc
)
target_include_directories(common PUBLIC ${PROJECT_SOURCE_DIR}/include ${Python3_INCLUDE_DIRS})

if(HAS_BTF_SUPPORT)
    message(STATUS "Enabling BPF modules with BTF support")
    add_subdirectory(src/os)
else()
    message(WARNING "Disabling BPF modules (no BTF support)")
endif()

add_library(sysTrace_hook SHARED
    ${PROJECT_SOURCE_DIR}/include/common/shared_constants.c
    ${PROJECT_SOURCE_DIR}/src/trace/systrace_manager.cc
    ${PROJECT_SOURCE_DIR}/src/trace/library_loader.cc
    ${PROJECT_SOURCE_DIR}/src/trace/python/pytorch_tracing_loader.cc
    ${PROJECT_SOURCE_DIR}/src/trace/python/pytorch_tracing_manager.cc
    ${PROJECT_SOURCE_DIR}/src/trace/python/pytorch_tracing.c
    ${PROJECT_SOURCE_DIR}/src/ascend/hook.cc
    ${PROJECT_SOURCE_DIR}/server/monitor_server.cpp
)

add_executable(sysTrace_cli
    ${PROJECT_SOURCE_DIR}/client/sysTracecli.cpp
)

set_target_properties(sysTrace_hook PROPERTIES OUTPUT_NAME "sysTrace")

target_link_libraries(sysTrace_hook
    common
    ${Python3_LIBRARIES}
    ${CMAKE_THREAD_LIBS}
    pthread
    -ldl
)

if(HAS_BTF_SUPPORT)
    target_link_libraries(sysTrace_hook os_probe)
    message(STATUS "Linking osprobe library")
endif()