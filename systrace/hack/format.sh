#!/bin/bash

function install_clang_format() {
    if ! command -v clang-format &> /dev/null; then
        echo "Installing clang-format..."
        if command -v apt &> /dev/null; then
            sudo apt install -y clang-format
        elif command -v yum &> /dev/null; then
            sudo yum install -y clang-format
        else
            echo "Error: Cannot install clang-format (unsupported package manager)."
            exit 1
        fi
    else
        echo "clang-format is already installed."
    fi
}

function setup_clang_format() {
    local clang_format_file=".clang-format"
    if [ ! -f "$clang_format_file" ]; then
        echo "Creating .clang-format with 4-space indentation and Allman braces..."
        cat > "$clang_format_file" <<EOF
BasedOnStyle: LLVM
IndentWidth: 4
BreakBeforeBraces: Allman
UseTab: Never
TabWidth: 4
EOF
    else
        echo ".clang-format already exists. Modify it manually if needed."
    fi
}

function format_code() {
    echo "Formatting C/C++ files..."
    find . -type f \( -name "*.c" -o -name "*.h" -o -name "*.cpp" -o -name "*.hpp" -o -name "*.cc" -o -name "*.cxx" \) \
        | grep -v "pb-c" \
        | xargs clang-format -i -style=file
    echo "Formatting complete!"
}

install_clang_format
setup_clang_format
format_code