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

if [ "$PROTOC_VERSION" -ge 3 ]; then
    PROTO_FILE="systrace.v3.proto"
else
    PROTO_FILE="systrace.v2.proto"
fi

cd protos
protoc --c_out=. $PROTO_FILE
protoc --cpp_out=. $PROTO_FILE
protoc --python_out=. $PROTO_FILE
cd ..

cd build
cmake ..
make -j $(nproc)