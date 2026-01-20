#!/bin/bash

function install_clang_format() {
    if ! command -v clang-format &> /dev/null; then
        if command -v apt &> /dev/null; then
            sudo apt install -y clang-format
        elif command -v yum &> /dev/null; then
            sudo yum install -y clang-format
        else
            exit 1
        fi
    fi
}

function setup_clang_format() {
    local clang_format_file=".clang-format"
    cat > "$clang_format_file" <<EOF
BasedOnStyle: LLVM
IndentWidth: 4
BreakBeforeBraces: Attach
UseTab: Never
TabWidth: 4
AllowShortBlocksOnASingleLine: true
EOF
}

function format_code() {
    local script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    local project_root="$(cd "$script_dir/.." && pwd)"
    
    cd "$project_root" || exit

    find . -path "./thirdparty" -prune -o -type f -not -name "*bpf.c"  \( -name "*.c" -o -name "*.h" -o -name "*.cpp" -o -name "*.hpp" -o -name "*.cc" -o -name "*.cxx" \) -print | xargs clang-format -i -style=file
}

install_clang_format
setup_clang_format
format_code