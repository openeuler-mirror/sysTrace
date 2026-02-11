#!/bin/bash

MODE=${1:-"proto"}
CONFIG_DIR="/etc/systrace/config"
PY_FUNC_LIST="config/PyFuncList"
BPF_MOUNT="/sys/fs/bpf"
PROTOS_DIR="protos"
BUILD_DIR="build"

cleanup() {
    mkdir -p "$BUILD_DIR" "$CONFIG_DIR"
    rm -rf "$BUILD_DIR"/*
    rm -rf "$BPF_MOUNT/sysTrace"
    mount -t bpf bpf "$BPF_MOUNT/" 2>/dev/null || true
    rm -f src/os/*.{o,skel.h}
}

setup_config() {
    [ -f "$PY_FUNC_LIST" ] && cp -f "$PY_FUNC_LIST" "$CONFIG_DIR/"
}

compile_proto() {
    if [ "$MODE" == "json" ]; then
        echo "JSON Mode detected. Skipping Protobuf compilation."
        return
    fi

    echo "Compiling Protobuf definitions..."
    cd "$PROTOS_DIR"
    PROTOC_VERSION=$(protoc --version | awk '{print $2}' | cut -d. -f1)
    if [ "$PROTOC_VERSION" -ge 3 ]; then
        cp systrace.v3.proto systrace.proto
    else
        cp systrace.v2.proto systrace.proto
    fi
    protoc --{c,cpp,python}_out=. systrace.proto
    cd ..
}

check_btf() {
    [ -f "/sys/kernel/btf/vmlinux" ] && return 0
    grep -q "CONFIG_DEBUG_INFO_BTF=y" "/boot/config-$(uname -r)" 2>/dev/null && return 0
    return 1
}

check_bpf() {
    grep -q "CONFIG_BPF_SYSCALL=y" "/boot/config-$(uname -r)" 2>/dev/null && return 0
    [ -f "/proc/config.gz" ] && zgrep -q "CONFIG_BPF_SYSCALL=y" /proc/config.gz 2>/dev/null && return 0
    [ -f "/proc/sys/net/core/bpf_jit_enable" ] && return 0
    mount | grep -q "type bpf" && return 0
    return 1
}

build() {
    cd "$BUILD_DIR"
    cmake_flags=""

    if [ "$MODE" == "json" ]; then
        cmake_flags="-DUSE_JSON_FORMAT=ON"
    else
        cmake_flags="-DUSE_JSON_FORMAT=OFF"
    fi

    check_btf && cmake_flags="$cmake_flags -DHAS_BTF_SUPPORT=ON" || cmake_flags="$cmake_flags -DHAS_BTF_SUPPORT=OFF"
    check_bpf && f_bpf="-DHAS_BPF_SUPPORT=ON" || f_bpf="-DHAS_BPF_SUPPORT=OFF"
    cmake .. $cmake_flags $f_bpf
    make -j $(nproc)
    cd ..
}

main() {
    cleanup
    setup_config
    compile_proto
    build
}

main "$@"