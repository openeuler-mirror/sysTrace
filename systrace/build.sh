#!/bin/bash

sudo dnf remove -y libunwind libunwind-devel 2>/dev/null || true
mkdir -p build

cd protos
protoc --c_out=. systrace.proto
protoc --cpp_out=. systrace.proto
protoc --python_out=. systrace.proto
cd ..
cd build
cmake ..
make -j $(nproc)
