#include <Python.h>
#include <frameobject.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>

#include "../../../include/common/shared_constants.h"
#include "../../../thirdparty/uthash.h"
#include "pytorch_tracing_data.h"

#ifdef __cplusplus
extern "C"
{
#endif
    __attribute__((visibility("default"))) PyTorchTracingDataArray *
    systrace_get_empty_pytorch_tracing_data_array(int);
    __attribute__((visibility("default"))) PyTorchTracingDataArray *
    systrace_get_full_pytorch_tracing_data_array(int);

    __attribute__((visibility("default"))) PyTorchTracingDataArray *
    systrace_get_partial_pytorch_tracing_data_array(int);

    __attribute__((visibility("default"))) void
    systrace_return_pytorch_tracing_data_array(PyTorchTracingDataArray *,
                                               int type, int name);
    __attribute__((visibility("default"))) void
    systrace_register_tracing(const char **, int, char **);
#ifdef __cplusplus
}
#endif
typedef struct
{
    int64_t py_code_address;
    const char *function_name;
    int tag_name;
    int is_native;
    UT_hash_handle hh;
} TracingFunction;

typedef struct
{
    int tag_name;
    PyTorchTracingDataArray *curr_data;
    int64_t count;
    const char *function_name;
} TracingData;

typedef struct _frame PyFrameObject;
uint64_t getCodeOfFrame(PyFrameObject *frame);
static void capture_stack(PyFrameObject *frame,
                          PyTorchTracingData *trace_entry);

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

static TracingData *pytorch_tracing_data_array = NULL;

static TracingFunction *pytorch_tracing_func_map = NULL;
static int start_tracing = 1;
static int tracing_data_count = 0;

static int GetFuncAddressByPython(const char *input, char **error_message,
                                  int64_t *code_address, int *is_native);
static uint64_t getMsTime();
static TracingFunction *isTracedPyTorchFunction(PyFrameObject *frame);
static TracingData *receiveTracingData(int name);
static void addTracingData(int name, const char *func_name);
static int profiler(PyObject *obj, PyFrameObject *frame, int what,
                    PyObject *arg);