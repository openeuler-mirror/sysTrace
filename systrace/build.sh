#!/bin/bash

CONFIG_DIR="/etc/systrace/config"
SCRIPT_DIR="/etc/systrace/scripts"
PY_FUNC_LIST="config/PyFuncList"
MUTEX_SCRIPT="scripts/bpftrace_all_mutex.bt"
BPF_MOUNT="/sys/fs/bpf"
PROTOS_DIR="protos"
BUILD_DIR="build"

cleanup() {
    mkdir -p "$BUILD_DIR" "$CONFIG_DIR"
    rm -rf "$BPF_MOUNT/sysTrace"
    mount -t bpf bpf "$BPF_MOUNT/" 2>/dev/null || true
    rm -f src/os/*.{o,skel.h}
}

setup_config() {
    mkdir -p "$SCRIPT_DIR"
    [ -f "$PY_FUNC_LIST" ] && cp -f "$PY_FUNC_LIST" "$CONFIG_DIR/"
    [ -f "$MUTEX_SCRIPT" ] && cp -f "$MUTEX_SCRIPT" "$SCRIPT_DIR/"
}

compile_proto() {
    cd "$PROTOS_DIR"
    PROTOC_VERSION=$(protoc --version | awk '{print $2}' | cut -d. -f1)
    PROTO_FILE=""
    PROTO_EXTRA_OPT=""

    if [ "$PROTOC_VERSION" -ge 3 ]; then
        mv systrace.v3.proto systrace.proto
    else
        mv systrace.v2.proto systrace.proto
    fi
    protoc --{c,cpp,python}_out=. systrace.proto
    cd ..
}

check_btf() {
    [ -f "/sys/kernel/btf/vmlinux" ] && return 0
    grep -q "CONFIG_DEBUG_INFO_BTF=y" "/boot/config-$(uname -r)" 2>/dev/null && return 0
    return 1
}

build() {
    cd "$BUILD_DIR"
    cmake_flags=""
    check_btf && cmake_flags="-DHAS_BTF_SUPPORT=ON" || cmake_flags="-DHAS_BTF_SUPPORT=OFF"
    cmake .. $cmake_flags
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