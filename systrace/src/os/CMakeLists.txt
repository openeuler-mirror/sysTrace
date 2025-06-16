cmake_minimum_required(VERSION 3.10)
project(os_probe)
set(CMAKE_VERBOSE_MAKEFILE ON)

# Set compiler flags
set(CMAKE_C_FLAGS "-g -O2 -Wall -fPIC -std=gnu11")
set(CMAKE_CXX_FLAGS "-std=c++11 -g -O2 -Wall -fPIC")
set(BPFTOOL bpftool)
# Find required libraries
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBBPF REQUIRED libbpf)
pkg_check_modules(PROTOBUF_C REQUIRED libprotobuf-c)

# BPF compilation
set(BPF_SOURCES
    ${PROJECT_SOURCE_DIR}/os_cpu.bpf.c
    ${PROJECT_SOURCE_DIR}/os_mem.bpf.c
)

add_custom_target(ebpf_kern
	COMMAND bpftool btf dump file /sys/kernel/btf/vmlinux format c > ${PROJECT_SOURCE_DIR}/vmlinux.h
)

foreach(bpf_src ${BPF_SOURCES})
    get_filename_component(bpf_name ${bpf_src} NAME_WE)
    add_custom_command(
        OUTPUT ${PROJECT_SOURCE_DIR}/${bpf_name}.bpf.o
        COMMAND clang -target bpf -g -O2 -I${PROJECT_SOURCE_DIR} -c ${bpf_src} -o ${PROJECT_SOURCE_DIR}/${bpf_name}.bpf.o
        DEPENDS ${bpf_src}
        COMMENT "Building BPF object ${bpf_name}"
    )
    list(APPEND BPF_OBJECTS ${PROJECT_SOURCE_DIR}/${bpf_name}.bpf.o)
endforeach()

foreach(bpf_obj ${BPF_OBJECTS})
    get_filename_component(bpf_obj_name ${bpf_obj} NAME_WE)
    add_custom_command(
            OUTPUT ${PROJECT_SOURCE_DIR}/${bpf_obj_name}.skel.h
            COMMAND ${BPFTOOL} gen skeleton ${bpf_obj} > ${PROJECT_SOURCE_DIR}/${bpf_obj_name}.skel.h
            DEPENDS ${bpf_obj} ${BPF_OBJECTS}
    )
    list(APPEND BPF_SKEL_H ${PROJECT_SOURCE_DIR}/${bpf_obj_name}.skel.h)
endforeach()

add_custom_target(generate_skel_h_${PROJECT_NAME} ALL DEPENDS ebpf_kern ${BPF_OBJECTS} ${BPF_SKEL_H})

# Main source files
set(SOURCES
    os_probe.c
)

# Create shared library
add_library(os_probe OBJECT ${SOURCES})
add_dependencies(os_probe generate_skel_h_${PROJECT_NAME})

# Link libraries
target_link_libraries(os_probe
    ${LIBBPF_LIBRARIES}
    ${PROTOBUF_C_LIBRARIES}
    pthread
    z
    stdc++
)

# Install
install(TARGETS os_probe LIBRARY DESTINATION lib)
