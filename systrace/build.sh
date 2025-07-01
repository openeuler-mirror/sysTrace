#!/bin/bash

sudo dnf remove -y libunwind libunwind-devel 2>/dev/null || true
mkdir -p build
mkdir -p /etc/systrace/config
rm /sys/fs/bpf/sysTrace -rf
mount -t bpf bpf /sys/fs/bpf/
rm src/os/*.o -rf
rm src/os/*.skel.h -rf

cp -f config/PyFuncList /etc/systrace/config/PyFuncList

cd protos
protoc --c_out=. systrace.proto
protoc --cpp_out=. systrace.proto
protoc --python_out=. systrace.proto
cd ..
cd build
cmake ..
make -j $(nproc)