cmake_minimum_required(VERSION 3.10)
project(sysTrace)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_SKIP_RPATH TRUE)
set(CMAKE_BUILD_WITH_INSTALL_RPATH FALSE)
set(CMAKE_INSTALL_RPATH "")
set(CMAKE_INSTALL_RPATH_USE_LINK_PATH FALSE)
if(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|ARM64")
    set(UNWIND_LIB "unwind-aarch64")
    set(MSPTI_INCLUDE "${PROJECT_SOURCE_DIR}/thirdparty/aarch64/mspti/include")
    set(MSPTI_LIB "${PROJECT_SOURCE_DIR}/thirdparty/aarch64/mspti/lib64")
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64")
    set(UNWIND_LIB "unwind")
    set(MSPTI_INCLUDE "${PROJECT_SOURCE_DIR}/thirdparty/x86_64/mspti/include")
    set(MSPTI_LIB "${PROJECT_SOURCE_DIR}/thirdparty/x86_64/mspti/lib64")
else()
    message(WARNING "Unknown architecture: ${CMAKE_SYSTEM_PROCESSOR}")
    set(UNWIND_LIB "unwind")
endif()
include_directories(
    ${MSPTI_INCLUDE}
)

find_package(Python3 REQUIRED COMPONENTS Development)
find_package(Protobuf REQUIRED)
find_package(Threads REQUIRED)

find_library(ASCEND_MSPTI 
    NAMES mspti
    HINTS ${MSPTI_LIB}
)
if(NOT ASCEND_MSPTI)
    message(FATAL_ERROR "Ascend mspti library not found!")
endif()

add_library(common STATIC
    ${PROJECT_SOURCE_DIR}/include/common/logging.cc
    ${PROJECT_SOURCE_DIR}/include/common/util.cc
)
target_include_directories(common PUBLIC ${PROJECT_SOURCE_DIR}/include ${Python3_INCLUDE_DIRS})


add_subdirectory(protos)

add_library(sysTrace_hook SHARED
    ${PROJECT_SOURCE_DIR}/src/trace/systrace_manager.cc
    ${PROJECT_SOURCE_DIR}/src/trace/library_loader.cc
    ${PROJECT_SOURCE_DIR}/src/trace/python/pytorch_tracing_loader.cc
    ${PROJECT_SOURCE_DIR}/src/trace/python/pytorch_tracing_manager.cc
    ${PROJECT_SOURCE_DIR}/src/trace/python/pytorch_tracing.c
    ${PROJECT_SOURCE_DIR}/src/ascend/hook.cc
    ${PROJECT_SOURCE_DIR}/src/mspti/mspti_tracker.cpp
    ${PROJECT_SOURCE_DIR}/src/cann/cann_hook.c
)

set_target_properties(sysTrace_hook PROPERTIES OUTPUT_NAME "sysTrace")

target_link_libraries(sysTrace_hook
    common
    general_pb2
    ${Python3_LIBRARIES}
    protobuf::libprotobuf
    ${CMAKE_THREAD_LIBS}
    pthread
    jsoncpp
    -ldl
)
