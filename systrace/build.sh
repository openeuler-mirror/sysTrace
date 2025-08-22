#!/bin/bash

CONFIG_DIR="/etc/systrace/config"
PY_FUNC_LIST="config/PyFuncList"
BPF_MOUNT="/sys/fs/bpf"
PROTOS_DIR="protos"
BUILD_DIR="build"

cleanup() {
    mkdir -p "$BUILD_DIR" "$CONFIG_DIR"
    sudo rm -rf "$BPF_MOUNT/sysTrace"
    sudo mount -t bpf bpf "$BPF_MOUNT/" 2>/dev/null || true
    rm -f src/os/*.{o,skel.h}
}

setup_config() {
    [ -f "$PY_FUNC_LIST" ] && sudo cp -f "$PY_FUNC_LIST" "$CONFIG_DIR/"
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