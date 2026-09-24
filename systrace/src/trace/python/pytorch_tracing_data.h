#pragma once
#include <stdint.h>

#ifndef PY_TRACING_BUFFER_SIZE
#define PY_TRACING_BUFFER_SIZE 512
#define PY_TRACING_MAX_THREADS 256
#endif
#ifndef PY_TRACING_MAX_ACTIVE_EVENTS
/* Bound per-thread in-flight records; deeper nesting is dropped fail-locally. */
#define PY_TRACING_MAX_ACTIVE_EVENTS 64
#endif
#ifndef PY_TRACING_MONITORING_TOOL_ID
/* PEP 669 user-tool slot; override at build time if the slot is occupied. */
#define PY_TRACING_MONITORING_TOOL_ID 4
#endif
#ifndef PY_TRACING_MONITORING_FALLBACK_TOOL_ID
#define PY_TRACING_MONITORING_FALLBACK_TOOL_ID 3
#endif
#define PY_TRACING_READY_POOL 0
#define PY_TRACING_EMPTY_POOL 1
#define PY_TRACING_GC 0
#define PY_DATALOADER 1

#ifndef MAX_STACK_DEPTH
/* Keep the hot-path stack bounded; override with -DMAX_STACK_DEPTH=32 if needed. */
#define MAX_STACK_DEPTH 8
#endif
#define MAX_STACK_FRAME_LENGTH 256

typedef enum {
    PAYLOAD_UNINITIALIZED = 0,
    PAYLOAD_GC = 1,
} PayloadType;

typedef enum {
    UNKNOWN = 0,
    DATALOADER,
    FORWARD,
    BACKWARD,
    SYNCHRONIZATION,
    GC,
} Stagetype;

typedef union {
    int gc_debug[2];
} Payload;

typedef struct {
    uint64_t start;
    uint64_t end;
    uint32_t count;
    uint32_t stage_id;
    Stagetype stage_type;
    Payload payload;
    PayloadType type;
    char stack_info[MAX_STACK_DEPTH][MAX_STACK_FRAME_LENGTH];
    int stack_depth;
} PyTorchTracingData;

typedef struct {
    PyTorchTracingData data[PY_TRACING_BUFFER_SIZE];
    uint64_t cur;
} PyTorchTracingDataArray;
