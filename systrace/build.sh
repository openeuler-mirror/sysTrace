#!/bin/bash

CONFIG_DIR="/etc/systrace/config"
PY_FUNC_LIST="config/PyFuncList"
BPF_MOUNT="/sys/fs/bpf"
BUILD_DIR="build"

cleanup() {
    mkdir -p "$BUILD_DIR" "$CONFIG_DIR"
}

setup_config() {
    [ -f "$PY_FUNC_LIST" ] && cp -f "$PY_FUNC_LIST" "$CONFIG_DIR/"
}

check_btf() {
    [ -f "/sys/kernel/btf/vmlinux" ] && return 0
    grep -q "CONFIG_DEBUG_INFO_BTF=y" "/boot/config-$(uname -r)" 2>/dev/null && return 0
    return 1
}

build() {
    cd "$BUILD_DIR"
    cmake ..
    make -j $(nproc)
    cd ..
}

main() {
    cleanup
    setup_config
    build
}

main "$@"