#!/bin/bash

sudo dnf remove -y libunwind libunwind-devel 2>/dev/null || true
mkdir -p build
mkdir -p /etc/systrace/config
rm /sys/fs/bpf/sysTrace -rf
mount -t bpf bpf /sys/fs/bpf/
rm src/os/*.o -rf
rm src/os/*.skel.h -rf

cp -f config/PyFuncList /etc/systrace/config/PyFuncList

PROTOC_VERSION=$(protoc --version | awk '{print $2}' | cut -d. -f1)
PROTO_FILE=""
PROTO_EXTRA_OPT=""

cd protos
if [ "$PROTOC_VERSION" -ge 3 ]; then
    mv systrace.v3.proto systrace.proto
else
    mv systrace.v2.proto systrace.proto
fi
protoc --c_out=. systrace.proto
protoc --cpp_out=. systrace.proto
protoc --python_out=. systrace.proto
cd ..

cd build
cmake ..
make -j $(nproc)