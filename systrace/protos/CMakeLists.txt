project(general_pb2)

set(PB_FILES systrace.pb.cc systrace.pb-c.c)

add_library(${PROJECT_NAME} STATIC ${PB_FILES})

include_directories(${PROJECT_SOURCE_DIR}
    ${GOOGLE_PROTOBUF_DIR}/include
)

link_directories(${GOOGLE_PROTOBUF_DIR}/lib/)

target_link_libraries(${PROJECT_NAME}
    protobuf
    protobuf-c
)

