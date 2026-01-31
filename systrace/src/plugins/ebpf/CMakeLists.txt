cmake_minimum_required(VERSION 3.10)
project(ebpf_subsystem)

find_program(BPFTOOL bpftool REQUIRED)
find_program(CLANG clang REQUIRED)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBBPF REQUIRED libbpf)
pkg_check_modules(LIBDW REQUIRED libdw)
pkg_check_modules(LIBELF REQUIRED libelf)

set(BPF_SOURCES
    python_gil.bpf.c
    pthrd_sync.bpf.c
)

set(SKEL_HEADERS "")

foreach(bpf_src ${BPF_SOURCES})
    get_filename_component(bpf_name ${bpf_src} NAME_WE)

    set(bpf_obj ${CMAKE_CURRENT_BINARY_DIR}/${bpf_name}.bpf.o)
    set(skel_h ${CMAKE_CURRENT_BINARY_DIR}/${bpf_name}.skel.h)

    add_custom_command(
        OUTPUT ${bpf_obj}
        COMMAND ${CLANG} -target bpf -g -O2
        -D__BPF_TRACING__
        -I${CMAKE_CURRENT_SOURCE_DIR}
        -I/usr/include/${CMAKE_LIBRARY_ARCHITECTURE}
        -c ${CMAKE_CURRENT_SOURCE_DIR}/${bpf_src} -o ${bpf_obj}
        DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/${bpf_src}
        VERBATIM
        COMMENT "Compiling BPF object: ${bpf_name}"
    )

    add_custom_command(
        OUTPUT ${skel_h}
        COMMAND ${BPFTOOL} gen skeleton ${bpf_obj} > ${skel_h}
        DEPENDS ${bpf_obj}
        VERBATIM
        COMMENT "Generating skeleton: ${bpf_name}.skel.h"
    )

    list(APPEND SKEL_HEADERS ${skel_h})
endforeach()

add_custom_target(ebpf_gen ALL DEPENDS ${SKEL_HEADERS})

add_library(ebpf_module INTERFACE)
add_dependencies(ebpf_module ebpf_gen)

target_include_directories(ebpf_module INTERFACE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(ebpf_module INTERFACE
    ${LIBBPF_LIBRARIES}
    ${LIBDW_LIBRARIES}
    ${LIBELF_LIBRARIES}
)