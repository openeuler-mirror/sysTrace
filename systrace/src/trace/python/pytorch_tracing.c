#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include "pytorch_tracing.h"
#include <limits.h>
#include <stdlib.h>

/*
 * sysTrace is an LD_PRELOAD library and may also be loaded by non-Python
 * processes. Keep Python symbols weak so the loader can leave the Python
 * tracing backend unavailable instead of rejecting the whole preload.
 */
#if defined(__GNUC__) && !defined(_WIN32)
#pragma weak PyArg_ParseTuple
#pragma weak PyCMethod_New
#pragma weak PyCode_Type
#pragma weak PyDict_GetItemString
#pragma weak PyDict_New
#pragma weak PyErr_Clear
#pragma weak PyErr_Fetch
#pragma weak PyErr_NormalizeException
#pragma weak PyErr_Occurred
#pragma weak PyEval_GetFrame
#pragma weak PyEval_GetGlobals
#pragma weak PyEval_SetProfile
#pragma weak PyFrame_GetBack
#pragma weak PyFrame_GetCode
#pragma weak PyFrame_GetLineNumber
#pragma weak PyGILState_Ensure
#pragma weak PyGILState_Release
#pragma weak PyImport_ImportModule
#pragma weak PyList_Append
#pragma weak PyLong_AsLong
#pragma weak PyLong_AsLongLong
#pragma weak PyLong_AsUnsignedLong
#pragma weak PyObject_CallMethod
#pragma weak PyObject_GetAttrString
#pragma weak PyObject_Str
#pragma weak PyRun_StringFlags
#pragma weak PyThreadState_Get
#pragma weak PyThreadState_Next
#pragma weak PyThreadState_Swap
#pragma weak PyUnicode_AsUTF8
#pragma weak PyUnicode_CompareWithASCIIString
#pragma weak Py_Initialize
#pragma weak Py_IsInitialized
#pragma weak _PyObject_New
#pragma weak _Py_Dealloc
#pragma weak _Py_NoneStruct
#endif

typedef struct {
    /* In-flight records stay thread-local until the RETURN event commits them. */
    PyFrameObject *frame;
    uint64_t code_address;
    PyCodeObject *code_object;
    int tag_name;
    PyTorchTracingData data;
} ActiveTracingEvent;

#define PY_TRACING_LOOKUP_CACHE_SIZE 16
typedef struct {
    uint64_t code_address;
    TracingFunction *function;
} TracingFunctionCacheEntry;

static _Thread_local ActiveTracingEvent *active_tracing_events = NULL;
static _Thread_local uint32_t active_tracing_depth;
static _Thread_local uint32_t active_tracing_overflow;
static _Thread_local TracingFunctionCacheEntry
    tracing_function_cache[PY_TRACING_LOOKUP_CACHE_SIZE];

static int python_monitoring_enabled;
static int python_monitoring_tool_id = -1;
static PyObject *python_monitoring_module;
static PyObject *python_monitoring_start_callback;
static PyObject *python_monitoring_return_callback;
static PyObject *python_monitoring_unwind_callback;

typedef enum {
    PYTHON_MONITORING_EVENT_PY_START = 0,
    PYTHON_MONITORING_EVENT_PY_RESUME,
    PYTHON_MONITORING_EVENT_PY_RETURN,
    PYTHON_MONITORING_EVENT_PY_YIELD,
    PYTHON_MONITORING_EVENT_PY_UNWIND,
    PYTHON_MONITORING_EVENT_COUNT,
} PythonMonitoringEvent;

static unsigned int
    python_monitoring_event_masks[PYTHON_MONITORING_EVENT_COUNT];

static int set_monitoring_local_events(PyObject *code_object);
static int initialize_python_monitoring(void);

static ActiveTracingEvent *get_active_tracing_events(void) {
    if (!active_tracing_events) {
        active_tracing_events = (ActiveTracingEvent *)calloc(
            PY_TRACING_MAX_ACTIVE_EVENTS, sizeof(ActiveTracingEvent));
    }
    return active_tracing_events;
}

static size_t append_stack_text(char *buffer, size_t position,
                                const char *text) {
    if (position >= MAX_STACK_FRAME_LENGTH - 1) {
        return MAX_STACK_FRAME_LENGTH - 1;
    }

    if (!text) {
        text = "unknown";
    }

    size_t available = MAX_STACK_FRAME_LENGTH - 1 - position;
    size_t length = strnlen(text, available);
    memcpy(buffer + position, text, length);
    return position + length;
}

static size_t append_stack_integer(char *buffer, size_t position, int value) {
    char digits[sizeof(int) * 3 + 1];
    uint64_t number = value;
    size_t length = 0;

    if (value < 0 && position < MAX_STACK_FRAME_LENGTH - 1) {
        buffer[position++] = '-';
        number = (uint64_t)(-(int64_t)value);
    } else if (value < 0) {
        return position;
    }

    do {
        digits[length++] = (char)('0' + number % 10);
        number /= 10;
    } while (number != 0);

    while (length > 0 && position < MAX_STACK_FRAME_LENGTH - 1) {
        buffer[position++] = digits[--length];
    }
    return position;
}

static void format_stack_frame(char *buffer, const char *name,
                               const char *file, int line) {
    size_t position = 0;
    position = append_stack_text(buffer, position, name);
    position = append_stack_text(buffer, position, "@");
    position = append_stack_text(buffer, position, file);
    position = append_stack_text(buffer, position, ":");
    position = append_stack_integer(buffer, position, line);
    buffer[position] = '\0';
}

Stagetype determine_stage_type(const char *function_name) {
    if (function_name == NULL) {
        return UNKNOWN;
    }

    if (strcmp(function_name, "GC") == 0) {
        return GC;
    }
    if (strcmp(function_name,
               "torch.utils.data.dataloader@_BaseDataLoaderIter@__next__") ==
        0) {
        return DATALOADER;
    }
    if (strcmp(function_name, "torch_npu@npu@synchronize") == 0 ||
        strcmp(function_name, "torch_npu.npu@Event@synchronize") == 0 ||
        strcmp(function_name, "torch_npu.npu@Event@wait") == 0 ||
        strcmp(function_name, "torch_npu.npu@Stream@synchronize") == 0 ||
        strcmp(function_name, "torch_npu.npu@Stream@wait_event") == 0 ||
        strcmp(function_name, "torch_npu.npu@Stream@wait_stream") == 0) {
        return SYNCHRONIZATION;
    }
    if (strcmp(function_name, "torch@autograd@backward") == 0 ||
        strcmp(function_name, "torch@autograd@grad") == 0) {
        return BACKWARD;
    }
    if (strcmp(function_name,
               "megatron.core.pipeline_parallel@schedules@forward_step") == 0) {
        return FORWARD;
    }
    if (strcmp(function_name,
               "megatron.core.pipeline_parallel@schedules@backward_step") ==
        0) {
        return BACKWARD;
    }
    return UNKNOWN;
}

static int register_tracing_function(const char *name, int index,
                                     char **errors) {
    int64_t code_address;
    int is_native;
    PyObject *code_object = NULL;
    int ret =
        GetFuncAddressByPython(name, errors + index, &code_address, &is_native,
                               &code_object);

    if (ret) {
        systrace_log_error("PyTorchTrace", "register function `%s` error",
                           name);
        return ret;
    }

    systrace_log_info("PyTorchTrace", "register function `%s` at address %ld",
                      name, code_address);
    addTracingData(index, name);

    TracingFunction *traced_function =
        (TracingFunction *)malloc(sizeof(TracingFunction));
    traced_function->tag_name = index;
    traced_function->function_name = strdup(name);
    traced_function->py_code_address = code_address;
    traced_function->is_native = is_native;
    traced_function->stage_type = (int)determine_stage_type(name);

    HASH_ADD(hh, pytorch_tracing_func_map, py_code_address, sizeof(int64_t),
             traced_function);

    if (python_monitoring_enabled && code_object &&
        !set_monitoring_local_events(code_object)) {
        systrace_log_error("PyTorchTrace",
                           "enable local monitoring for `%s` failed", name);
    }
    Py_XDECREF(code_object);

    return 0;
}

static void set_profiler_for_all_threads() {
    PyEval_SetProfile(profiler, NULL);

    PyThreadState *tstate = PyThreadState_Get();
    PyThreadState *thread_array[PY_TRACING_MAX_THREADS];
    memset(thread_array, 0, sizeof(thread_array));

    int thread_count = 0;
    while (tstate != NULL && thread_count < PY_TRACING_MAX_THREADS) {
        thread_array[thread_count++] = tstate;
        systrace_log_info("PyTorchTrace", "Set profiler for thread %ld",
                          tstate->thread_id);
        tstate = PyThreadState_Next(tstate);
    }

    for (int i = 0; i < thread_count; i++) {
        PyThreadState_Swap(thread_array[i]);
        PyEval_SetProfile(profiler, NULL);
    }

    PyThreadState_Swap(thread_array[0]);
}

#if PY_MAJOR_VERSION >= 3 && PY_MINOR_VERSION >= 11
static void capture_stack(PyFrameObject *frame,
                          PyCodeObject *first_code,
                          PyTorchTracingData *trace_entry) {
    PyFrameObject *current_frame = frame;
    int owns_current_frame = 0;
    PyCodeObject *code = first_code;
    int owns_code = 0;
    int depth = 0;
    while (current_frame && depth < MAX_STACK_DEPTH) {
        if (!code) {
            code = PyFrame_GetCode(current_frame);
            owns_code = 1;
        }
        if (!code) {
            break;
        }

        PyObject *name_object =
            PyObject_GetAttrString((PyObject *)code, "co_name");
        PyObject *file_object =
            PyObject_GetAttrString((PyObject *)code, "co_filename");
        const char *name = name_object ? PyUnicode_AsUTF8(name_object) : NULL;
        const char *file = file_object ? PyUnicode_AsUTF8(file_object) : NULL;
        int line = PyFrame_GetLineNumber(current_frame);

        if (!name_object || !file_object || !name || !file)
            PyErr_Clear();

        format_stack_frame(trace_entry->stack_info[depth], name, file, line);

        Py_XDECREF(name_object);
        Py_XDECREF(file_object);

        PyFrameObject *next_frame = PyFrame_GetBack(current_frame);
        if (owns_code) {
            Py_DECREF(code);
        }
        code = NULL;
        owns_code = 0;
        if (owns_current_frame) {
            Py_DECREF(current_frame);
        }
        current_frame = next_frame;
        owns_current_frame = 1;

        depth++;
    }
    if (owns_current_frame) {
        Py_XDECREF(current_frame);
    }
    if (owns_code) {
        Py_XDECREF(code);
    }
    trace_entry->stack_depth = depth;
}

uint64_t getCodeOfFrame(PyFrameObject *frame) {
    PyCodeObject *code = PyFrame_GetCode(frame);
    uint64_t code_address = (uint64_t)(uintptr_t)code;
    Py_XDECREF(code);
    return code_address;
}
#else
static void capture_stack(PyFrameObject *frame,
                          PyCodeObject *first_code,
                          PyTorchTracingData *trace_entry) {
    (void)first_code;
    int depth = 0;
    while (frame && depth < MAX_STACK_DEPTH) {
        format_stack_frame(
            trace_entry->stack_info[depth],
            PyUnicode_AsUTF8(frame->f_code->co_name),
            PyUnicode_AsUTF8(frame->f_code->co_filename),
            PyFrame_GetLineNumber(frame));
        frame = frame->f_back;
        depth++;
    }
    trace_entry->stack_depth = depth;
}

uint64_t getCodeOfFrame(PyFrameObject *frame) {
    return (int64_t)(uintptr_t)(frame->f_code);
}

#endif

static int python_runtime_available(void) {
    return PyArg_ParseTuple && PyCMethod_New && &PyCode_Type &&
           PyDict_GetItemString && PyDict_New && PyErr_Clear && PyErr_Fetch &&
           PyErr_NormalizeException && PyErr_Occurred && PyEval_GetFrame &&
           PyEval_GetGlobals && PyEval_SetProfile && PyFrame_GetBack &&
           PyFrame_GetCode && PyFrame_GetLineNumber && PyGILState_Ensure &&
           PyGILState_Release && PyImport_ImportModule && PyList_Append &&
           PyLong_AsLong && PyLong_AsLongLong && PyLong_AsUnsignedLong &&
           PyObject_CallMethod && PyObject_GetAttrString && PyObject_Str &&
           PyRun_StringFlags && PyThreadState_Get && PyThreadState_Next &&
           PyThreadState_Swap && PyUnicode_AsUTF8 &&
           PyUnicode_CompareWithASCIIString && Py_IsInitialized &&
           Py_Initialize && &_PyObject_New && &_Py_Dealloc &&
           &_Py_NoneStruct;
}

static int ensure_python_initialized() {
    if (!python_runtime_available())
        return 0;

    if (!Py_IsInitialized()) {
        if (!Py_Initialize)
            return 0;
        Py_Initialize();
    }
    return 1;
}

static TracingFunction *find_traced_function(uint64_t code_address) {
    uint32_t cache_index =
        (uint32_t)((code_address >> 4) & (PY_TRACING_LOOKUP_CACHE_SIZE - 1));
    TracingFunctionCacheEntry *cache_entry =
        &tracing_function_cache[cache_index];
    if (__builtin_expect(cache_entry->code_address == code_address, 1)) {
        return cache_entry->function;
    }

    TracingFunction *traced_function = NULL;
    HASH_FIND(hh, pytorch_tracing_func_map, &code_address, sizeof(int64_t),
              traced_function);
    cache_entry->code_address = code_address;
    cache_entry->function = traced_function;
    return traced_function;
}

TracingFunction *isTracedPyTorchFunction(PyFrameObject *frame) {
    return find_traced_function(getCodeOfFrame(frame));
}

static void commit_active_tracing_event(ActiveTracingEvent *active) {
    /* Capture while the callback still owns the frame, outside the global lock. */
    if (active->frame && active->data.stack_depth == 0) {
        capture_stack(active->frame, active->code_object, &active->data);
    }

    pthread_mutex_lock(&mutex);
    TracingData *tracing_data = receiveTracingData(active->tag_name);
    PyTorchTracingDataArray *curr_data = tracing_data->curr_data;
    if (curr_data->cur == PY_TRACING_BUFFER_SIZE) {
        systrace_return_pytorch_tracing_data_array(
            curr_data, PY_TRACING_READY_POOL, active->tag_name);
        tracing_data->curr_data =
            systrace_get_empty_pytorch_tracing_data_array(active->tag_name);
        curr_data = tracing_data->curr_data;
    }

    PyTorchTracingData *trace_entry = &curr_data->data[curr_data->cur++];
    trace_entry->start = active->data.start;
    trace_entry->end = get_current_utc_us();
    trace_entry->count = tracing_data->count;
    trace_entry->stage_id = active->data.stage_id;
    trace_entry->stage_type = active->data.stage_type;
    trace_entry->type = PAYLOAD_UNINITIALIZED;
    trace_entry->stack_depth = active->data.stack_depth;
    if (trace_entry->stack_depth > 0) {
        memcpy(trace_entry->stack_info, active->data.stack_info,
               (size_t)trace_entry->stack_depth * MAX_STACK_FRAME_LENGTH);
    }
    tracing_data->count++;
    pthread_mutex_unlock(&mutex);
}

static int profiler(PyObject *obj, PyFrameObject *frame, int what,
                    PyObject *arg) {
    if (!start_tracing ||
        (what != PyTrace_CALL && what != PyTrace_RETURN)) {
        return 0;
    }

    if (what == PyTrace_RETURN) {
        if (active_tracing_overflow > 0) {
            if (isTracedPyTorchFunction(frame) != NULL) {
                active_tracing_overflow--;
            }
            return 0;
        }

        if (active_tracing_depth == 0) {
            return 0;
        }

        if (!active_tracing_events) {
            active_tracing_depth = 0;
            return 0;
        }

        ActiveTracingEvent *active =
            &active_tracing_events[active_tracing_depth - 1];
        if (active->frame != frame) {
            return 0;
        }

        commit_active_tracing_event(active);
        active_tracing_depth--;
        return 0;
    }

    TracingFunction *func_data = isTracedPyTorchFunction(frame);
    if (!func_data) {
        return 0;
    }

    if (active_tracing_overflow > 0 ||
        active_tracing_depth >= PY_TRACING_MAX_ACTIVE_EVENTS) {
        active_tracing_overflow++;
        return 0;
    }

    ActiveTracingEvent *events = get_active_tracing_events();
    if (!events) {
        active_tracing_overflow++;
        return 0;
    }

    ActiveTracingEvent *active = &events[active_tracing_depth++];
    active->frame = frame;
    active->code_address = func_data->py_code_address;
    active->code_object = NULL;
    active->tag_name = func_data->tag_name;
    active->data.type = PAYLOAD_UNINITIALIZED;
    active->data.stack_depth = 0;

    /* Stage state is shared with native hooks; keep this update lock-free. */
    active->data.start = get_current_utc_us();
    if (func_data->stage_type == DATALOADER) {
        active->data.stage_id =
            (uint32_t)__atomic_add_fetch(&global_stage_id, 1, __ATOMIC_RELAXED);
    } else {
        active->data.stage_id =
            (uint32_t)__atomic_load_n(&global_stage_id, __ATOMIC_RELAXED);
    }
    active->data.stage_type = func_data->stage_type;
    __atomic_store_n(&global_stage_type, func_data->stage_type,
                     __ATOMIC_RELAXED);

    return 0;
}

static void begin_monitoring_event(PyObject *code_object) {
    if (!start_tracing || !PyCode_Check(code_object))
        return;

    uint64_t code_address = (uint64_t)(uintptr_t)code_object;
    TracingFunction *func_data = find_traced_function(code_address);
    if (!func_data)
        return;

    if (active_tracing_overflow > 0 ||
        active_tracing_depth >= PY_TRACING_MAX_ACTIVE_EVENTS) {
        active_tracing_overflow++;
        return;
    }

    ActiveTracingEvent *events = get_active_tracing_events();
    if (!events) {
        active_tracing_overflow++;
        return;
    }

    ActiveTracingEvent *active = &events[active_tracing_depth++];
    active->frame = PyEval_GetFrame();
    active->code_address = code_address;
    active->code_object = (PyCodeObject *)code_object;
    active->tag_name = func_data->tag_name;
    active->data.type = PAYLOAD_UNINITIALIZED;
    active->data.stack_depth = 0;
    active->data.start = get_current_utc_us();
    if (func_data->stage_type == DATALOADER) {
        active->data.stage_id =
            (uint32_t)__atomic_add_fetch(&global_stage_id, 1, __ATOMIC_RELAXED);
    } else {
        active->data.stage_id =
            (uint32_t)__atomic_load_n(&global_stage_id, __ATOMIC_RELAXED);
    }
    active->data.stage_type = func_data->stage_type;
    __atomic_store_n(&global_stage_type, func_data->stage_type,
                     __ATOMIC_RELAXED);
}

static void finish_monitoring_event(PyObject *code_object) {
    if (!start_tracing || !PyCode_Check(code_object))
        return;

    uint64_t code_address = (uint64_t)(uintptr_t)code_object;
    if (!find_traced_function(code_address))
        return;

    if (active_tracing_overflow > 0) {
        active_tracing_overflow--;
        return;
    }

    if (active_tracing_depth == 0 || !active_tracing_events)
        return;

    ActiveTracingEvent *active =
        &active_tracing_events[active_tracing_depth - 1];
    if (active->code_address != code_address)
        return;

    commit_active_tracing_event(active);
    active_tracing_depth--;
}

static PyObject *monitoring_start_callback(PyObject *self,
                                           PyObject *const *args,
                                           Py_ssize_t nargs) {
    if (nargs > 0)
        begin_monitoring_event(args[0]);
    Py_RETURN_NONE;
}

static PyObject *monitoring_return_callback(PyObject *self,
                                            PyObject *const *args,
                                            Py_ssize_t nargs) {
    if (nargs > 0)
        finish_monitoring_event(args[0]);
    Py_RETURN_NONE;
}

static PyObject *monitoring_unwind_callback(PyObject *self,
                                            PyObject *const *args,
                                            Py_ssize_t nargs) {
    if (nargs > 0)
        finish_monitoring_event(args[0]);
    Py_RETURN_NONE;
}

static PyMethodDef monitoring_start_method = {
    "_systrace_monitoring_start",
    (PyCFunction)monitoring_start_callback,
    METH_FASTCALL,
    NULL,
};

static PyMethodDef monitoring_return_method = {
    "_systrace_monitoring_return",
    (PyCFunction)monitoring_return_callback,
    METH_FASTCALL,
    NULL,
};

static PyMethodDef monitoring_unwind_method = {
    "_systrace_monitoring_unwind",
    (PyCFunction)monitoring_unwind_callback,
    METH_FASTCALL,
    NULL,
};

static int register_monitoring_callback(unsigned int event_mask,
                                        PyObject *callback) {
    PyObject *result = PyObject_CallMethod(
        python_monitoring_module, "register_callback", "iiO",
        python_monitoring_tool_id, (int)event_mask, callback);
    if (!result)
        return 0;
    Py_DECREF(result);
    return 1;
}

static void unregister_monitoring_callback(unsigned int event_mask) {
    if (!python_monitoring_module || python_monitoring_tool_id < 0)
        return;
    PyObject *result = PyObject_CallMethod(
        python_monitoring_module, "register_callback", "iiO",
        python_monitoring_tool_id, (int)event_mask, Py_None);
    Py_XDECREF(result);
    PyErr_Clear();
}

static void disable_python_monitoring(void) {
    if (python_monitoring_module && python_monitoring_tool_id >= 0) {
        PyObject *result = PyObject_CallMethod(
            python_monitoring_module, "set_events", "iI",
            python_monitoring_tool_id, 0U);
        Py_XDECREF(result);
        PyErr_Clear();
        for (int i = 0; i < PYTHON_MONITORING_EVENT_COUNT; ++i) {
            if (python_monitoring_event_masks[i] != 0) {
                unregister_monitoring_callback(
                    python_monitoring_event_masks[i]);
            }
        }

        result = PyObject_CallMethod(python_monitoring_module, "free_tool_id",
                                     "i", python_monitoring_tool_id);
        Py_XDECREF(result);
        PyErr_Clear();
    }

    Py_CLEAR(python_monitoring_start_callback);
    Py_CLEAR(python_monitoring_return_callback);
    Py_CLEAR(python_monitoring_unwind_callback);
    Py_CLEAR(python_monitoring_module);
    python_monitoring_tool_id = -1;
    python_monitoring_enabled = 0;
    memset(python_monitoring_event_masks, 0,
           sizeof(python_monitoring_event_masks));
}

static int load_monitoring_event_mask(PyObject *events_module,
                                      PythonMonitoringEvent event,
                                      const char *event_name) {
    PyObject *event_object =
        PyObject_GetAttrString(events_module, event_name);
    if (!event_object)
        return 0;

    unsigned long mask = PyLong_AsUnsignedLong(event_object);
    Py_DECREF(event_object);
    if (PyErr_Occurred() || mask > UINT_MAX) {
        PyErr_Clear();
        return 0;
    }

    python_monitoring_event_masks[event] = (unsigned int)mask;
    return 1;
}

static int initialize_python_monitoring(void) {
    PyObject *sys_module = PyImport_ImportModule("sys");
    if (!sys_module)
        return 0;
    python_monitoring_module = PyObject_GetAttrString(sys_module, "monitoring");
    Py_DECREF(sys_module);
    if (!python_monitoring_module) {
        PyErr_Clear();
        return 0;
    }

    PyObject *events_module =
        PyObject_GetAttrString(python_monitoring_module, "events");
    if (!events_module)
        goto failed;

    const struct {
        PythonMonitoringEvent event;
        const char *name;
    } event_names[] = {
        {PYTHON_MONITORING_EVENT_PY_START, "PY_START"},
        {PYTHON_MONITORING_EVENT_PY_RESUME, "PY_RESUME"},
        {PYTHON_MONITORING_EVENT_PY_RETURN, "PY_RETURN"},
        {PYTHON_MONITORING_EVENT_PY_YIELD, "PY_YIELD"},
        {PYTHON_MONITORING_EVENT_PY_UNWIND, "PY_UNWIND"},
    };
    for (size_t i = 0; i < sizeof(event_names) / sizeof(event_names[0]);
         ++i) {
        if (!load_monitoring_event_mask(events_module, event_names[i].event,
                                        event_names[i].name)) {
            Py_DECREF(events_module);
            goto failed;
        }
    }
    Py_DECREF(events_module);

    const int tool_ids[] = {PY_TRACING_MONITORING_TOOL_ID,
                            PY_TRACING_MONITORING_FALLBACK_TOOL_ID};
    for (size_t i = 0; i < sizeof(tool_ids) / sizeof(tool_ids[0]); ++i) {
        PyObject *result = PyObject_CallMethod(
            python_monitoring_module, "use_tool_id", "is", tool_ids[i],
            "sysTrace");
        if (result) {
            Py_DECREF(result);
            python_monitoring_tool_id = tool_ids[i];
            break;
        }
        PyErr_Clear();
    }
    if (python_monitoring_tool_id < 0) {
        Py_CLEAR(python_monitoring_module);
        return 0;
    }

    python_monitoring_start_callback =
        PyCFunction_NewEx(&monitoring_start_method, NULL, NULL);
    python_monitoring_return_callback =
        PyCFunction_NewEx(&monitoring_return_method, NULL, NULL);
    python_monitoring_unwind_callback =
        PyCFunction_NewEx(&monitoring_unwind_method, NULL, NULL);
    if (!python_monitoring_start_callback ||
        !python_monitoring_return_callback ||
        !python_monitoring_unwind_callback)
        goto failed;

    if (!register_monitoring_callback(
            python_monitoring_event_masks[PYTHON_MONITORING_EVENT_PY_START],
                                      python_monitoring_start_callback) ||
        !register_monitoring_callback(
            python_monitoring_event_masks[PYTHON_MONITORING_EVENT_PY_RESUME],
                                      python_monitoring_start_callback) ||
        !register_monitoring_callback(
            python_monitoring_event_masks[PYTHON_MONITORING_EVENT_PY_RETURN],
                                      python_monitoring_return_callback) ||
        !register_monitoring_callback(
            python_monitoring_event_masks[PYTHON_MONITORING_EVENT_PY_YIELD],
                                      python_monitoring_return_callback) ||
        !register_monitoring_callback(
            python_monitoring_event_masks[PYTHON_MONITORING_EVENT_PY_UNWIND],
                                      python_monitoring_unwind_callback))
        goto failed;

    PyObject *result = PyObject_CallMethod(
        python_monitoring_module, "set_events", "iI", python_monitoring_tool_id,
        python_monitoring_event_masks[PYTHON_MONITORING_EVENT_PY_UNWIND]);
    if (!result)
        goto failed;
    Py_DECREF(result);
    python_monitoring_enabled = 1;
    return 1;

failed:
    PyErr_Clear();
    disable_python_monitoring();
    return 0;
}

static int set_monitoring_local_events(PyObject *code_object) {
    if (!python_monitoring_enabled || !python_monitoring_module ||
        !PyCode_Check(code_object))
        return 0;

    const unsigned int events =
        python_monitoring_event_masks[PYTHON_MONITORING_EVENT_PY_START] |
        python_monitoring_event_masks[PYTHON_MONITORING_EVENT_PY_RESUME] |
        python_monitoring_event_masks[PYTHON_MONITORING_EVENT_PY_RETURN] |
        python_monitoring_event_masks[PYTHON_MONITORING_EVENT_PY_YIELD];
    PyObject *result = PyObject_CallMethod(
        python_monitoring_module, "set_local_events", "iOI",
        python_monitoring_tool_id, code_object, events);
    if (!result) {
        PyErr_Clear();
        return 0;
    }
    Py_DECREF(result);
    return 1;
}

static int set_error_message(char **error_message, const char *format, ...) {
    va_list args;
    va_start(args, format);
    int size = vsnprintf(NULL, 0, format, args) + 1;
    va_end(args);

    *error_message = malloc(size);
    if (!*error_message)
        return 0;

    va_start(args, format);
    vsnprintf(*error_message, size, format, args);
    va_end(args);

    return 1;
}

static int parse_input_string(const char *code, char ***tokens,
                              int *token_count) {
    char *copy = strdup(code);
    if (!copy)
        return 0;

    char *saveptr = NULL;
    *token_count = 0;
    *tokens = malloc(3 * sizeof(char *));
    if (!*tokens) {
        free(copy);
        return 0;
    }

    for (char *token = strtok_r(copy, "@", &saveptr); token && *token_count < 3;
         token = strtok_r(NULL, "@", &saveptr)) {
        (*tokens)[(*token_count)++] = strdup(token);
    }

    free(copy);
    return 1;
}

static char *build_python_code(const char *code, char **tokens,
                               int token_count) {
    const char *template = "try:\n"
                           "    obj = None\n"
                           "    code_object = None\n"
                           "%s\n"
                           "    while hasattr(obj, '__wrapped__'):\n"
                           "        obj = getattr(obj, '__wrapped__')\n"
                           "    if hasattr(obj, '__code__'):\n"
                           "        code_object = obj.__code__\n"
                           "        address = id(code_object)\n"
                           "        is_native = 0\n"
                           "    else:\n"
                           "        address = id(obj)\n"
                           "        is_native = 1\n"
                           "except Exception as e:\n"
                           "    raise\n";

    char *import_part = NULL;
    if (token_count == 3) {
        asprintf(&import_part,
                 "    from %s import %s as mm\n"
                 "    obj = getattr(mm, '%s')",
                 tokens[0], tokens[1], tokens[2]);
    } else if (token_count == 2) {
        asprintf(&import_part, "    from %s import %s as obj", tokens[0],
                 tokens[1]);
    } else {
        asprintf(&import_part,
                 "    obj = globals().get('%s')\n"
                 "    if obj is None:\n"
                 "        raise ValueError('Global object not found: %s')",
                 code, code);
    }

    char *python_code = NULL;
    asprintf(&python_code, template, import_part);
    free(import_part);

    return python_code;
}

static int execute_python_code(const char *python_code, int use_globals,
                               int64_t *address, int *is_native,
                               PyObject **code_object, char **error_message) {
    PyObject *globals = use_globals ? PyEval_GetGlobals() : PyDict_New();
    PyObject *locals = PyDict_New();

    if (!globals || !locals) {
        if (!use_globals && globals)
            Py_DECREF(globals);
        if (locals)
            Py_DECREF(locals);
        return set_error_message(error_message,
                                 "Failed to create Python dictionaries");
    }

    PyObject *result =
        PyRun_String(python_code, Py_file_input, globals, locals);
    if (!result) {
        PyObject *ptype, *pvalue, *ptraceback;
        PyErr_Fetch(&ptype, &pvalue, &ptraceback);
        PyErr_NormalizeException(&ptype, &pvalue, &ptraceback);

        if (pvalue) {
            PyObject *py_str = PyObject_Str(pvalue);
            if (py_str) {
                const char *str_error = PyUnicode_AsUTF8(py_str);
                set_error_message(error_message, "Python error: %s",
                                  str_error ? str_error : "Unknown error");
                Py_DECREF(py_str);
            }
        }

        Py_XDECREF(ptype);
        Py_XDECREF(pvalue);
        Py_XDECREF(ptraceback);
        PyErr_Clear();

        if (!use_globals)
            Py_DECREF(globals);
        Py_DECREF(locals);
        return 1;
    }
    Py_DECREF(result);

    PyObject *py_address = PyDict_GetItemString(locals, "address");
    PyObject *py_is_native = PyDict_GetItemString(locals, "is_native");

    if (!py_address || !py_is_native) {
        if (!use_globals)
            Py_DECREF(globals);
        Py_DECREF(locals);
        return set_error_message(
            error_message, "Failed to get address or is_native from execution");
    }

    *address = PyLong_AsLongLong(py_address);
    *is_native = PyLong_AsLongLong(py_is_native);
    PyObject *py_code = PyDict_GetItemString(locals, "code_object");
    if (code_object && py_code && py_code != Py_None) {
        Py_INCREF(py_code);
        *code_object = py_code;
    }

    if (!use_globals)
        Py_DECREF(globals);
    Py_DECREF(locals);
    return 0;
}

static int GetFuncAddressByPython(const char *code, char **error_message,
                                  int64_t *address, int *is_native,
                                  PyObject **code_object) {
    *error_message = NULL;
    *address = 0;
    *is_native = 0;
    if (code_object)
        *code_object = NULL;

    if (!code || !*code) {
        return set_error_message(error_message, "Empty or NULL code parameter");
    }

    char **tokens = NULL;
    int token_count = 0;
    if (!parse_input_string(code, &tokens, &token_count)) {
        return set_error_message(error_message, "Failed to parse input string");
    }

    char *python_code = build_python_code(code, tokens, token_count);
    if (!python_code) {
        for (int i = 0; i < token_count; i++)
            free(tokens[i]);
        free(tokens);
        return set_error_message(error_message, "Failed to build Python code");
    }

    int use_globals = (token_count == 0);
    int result = execute_python_code(python_code, use_globals, address,
                                     is_native, code_object, error_message);

    free(python_code);
    for (int i = 0; i < token_count; i++)
        free(tokens[i]);
    free(tokens);

    if (result == 0) {
        set_error_message(error_message, "Get __code__ attribute for '%s' OK",
                          code);
    }

    return result;
}
static TracingData *receiveTracingData(int name) {
    return pytorch_tracing_data_array + name;
}

static void addTracingData(int name, const char *func_name) {
    TracingData *v = receiveTracingData(name);
    v->tag_name = name;
    v->curr_data = systrace_get_empty_pytorch_tracing_data_array(name);
    v->function_name = strdup(func_name);
}

static void getGcInfo(PyTorchTracingData *data, PyObject *info) {
    if (!PyDict_Check(info))
        return;
    PyObject *collected = PyDict_GetItemString(info, "collected");
    PyObject *uncollectable = PyDict_GetItemString(info, "uncollectable");

    if (collected && PyLong_Check(collected)) {
        data->payload.gc_debug[0] = PyLong_AsLong(collected);
    } else {
        data->payload.gc_debug[0] = -1;
    }

    if (uncollectable && PyLong_Check(uncollectable)) {
        data->payload.gc_debug[1] = PyLong_AsLong(uncollectable);
    } else {
        data->payload.gc_debug[1] = -1;
    }
}

static void gcCallback(PyObject *phase, PyObject *info) {
    pthread_mutex_lock(&mutex);
    if (PyUnicode_CompareWithASCIIString(phase, "start") == 0 &&
        start_tracing) {
        TracingData *tracing_data = receiveTracingData(PY_TRACING_GC);
        PyTorchTracingDataArray *curr_data = tracing_data->curr_data;
        if (curr_data->cur == PY_TRACING_BUFFER_SIZE) {
            systrace_return_pytorch_tracing_data_array(
                curr_data, PY_TRACING_READY_POOL, PY_TRACING_GC);
            tracing_data->curr_data =
                systrace_get_empty_pytorch_tracing_data_array(PY_TRACING_GC);
            curr_data = tracing_data->curr_data;
        }
        curr_data->data[curr_data->cur].start = get_current_utc_us();
        pthread_mutex_unlock(&mutex);
        return;
    } else if (PyUnicode_CompareWithASCIIString(phase, "stop") == 0) {
        TracingData *tracing_data = receiveTracingData(PY_TRACING_GC);
        if (start_tracing) {
            PyTorchTracingDataArray *curr_data = tracing_data->curr_data;
            curr_data->data[curr_data->cur].count = tracing_data->count;
            curr_data->data[curr_data->cur].stage_id =
                (uint32_t)__atomic_load_n(&global_stage_id, __ATOMIC_RELAXED);
            curr_data->data[curr_data->cur].type = PAYLOAD_GC;
            getGcInfo(curr_data->data + curr_data->cur, info);
            curr_data->data[curr_data->cur++].end = get_current_utc_us();
        }
        tracing_data->count++;
    }
    pthread_mutex_unlock(&mutex);
}

static PyObject *gcCallbackWrapper(PyObject *self, PyObject *args,
                                   PyObject *kwargs) {
    PyObject *phase, *info;
    if (!PyArg_ParseTuple(args, "OO", &phase, &info)) {
        return NULL;
    }
    gcCallback(phase, info);
    Py_RETURN_NONE;
}

static PyTypeObject GcCallbackType = {
    PyVarObject_HEAD_INIT(NULL, 0) "gc_callback", /* tp_name */
    sizeof(PyObject),                             /* tp_basicsize */
    0,                                            /* tp_itemsize */
    0,                                            /* tp_dealloc */
    0,                                            /* tp_vectorcall_offset */
    0,                                            /* tp_getattr */
    0,                                            /* tp_setattr */
    0,                                            /* tp_as_async */
    0,                                            /* tp_repr */
    0,                                            /* tp_as_number */
    0,                                            /* tp_as_sequence */
    0,                                            /* tp_as_mapping */
    0,                                            /* tp_hash  */
    gcCallbackWrapper,                            /* tp_call */
    0,                                            /* tp_str */
    0,                                            /* tp_getattro */
    0,                                            /* tp_setattro */
    0,                                            /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT,                           /* tp_flags */
    0,                                            /* tp_doc */
    0,                                            /* tp_traverse */
    0,                                            /* tp_clear */
    0,                                            /* tp_richcompare */
    0,                                            /* tp_weaklistoffset */
    0,                                            /* tp_iter */
    0,                                            /* tp_iternext */
    0,                                            /* tp_methods */
    0,                                            /* tp_members */
    0,                                            /* tp_getset */
    0,                                            /* tp_base */
    0,                                            /* tp_dict */
    0,                                            /* tp_descr_get */
    0,                                            /* tp_descr_set */
    0,                                            /* tp_dictoffset */
    0,                                            /* tp_init */
    0,                                            /* tp_alloc */
    0,                                            /* tp_new */
};

PyTorchTracingDataArray *
systrace_get_partial_pytorch_tracing_data_array(int name) {
    if (!pytorch_tracing_data_array || name < 0 ||
        name >= tracing_data_count) {
        return NULL;
    }

    pthread_mutex_lock(&mutex);
    TracingData *tracing_data = receiveTracingData(name);
    if ((!tracing_data || !tracing_data->curr_data) ||
        (tracing_data->curr_data->cur == 0)) {
        pthread_mutex_unlock(&mutex);
        return NULL;
    }
    PyTorchTracingDataArray *result = tracing_data->curr_data;
    tracing_data->curr_data =
        systrace_get_empty_pytorch_tracing_data_array(name);
    pthread_mutex_unlock(&mutex);
    return result;
}

void systrace_register_gc(char **error_message) {
    addTracingData(PY_TRACING_GC, "GC");
    PyObject *gc_module = PyImport_ImportModule("gc");
    if (!gc_module) {
        return;
    }

    PyObject *callbacks_list = PyObject_GetAttrString(gc_module, "callbacks");
    if (!callbacks_list || !PyList_Check(callbacks_list)) {
        Py_XDECREF(callbacks_list);
        Py_DECREF(gc_module);
        return;
    }

    PyObject *py_callback = PyObject_New(PyObject, &GcCallbackType);

    if (!py_callback) {
        Py_DECREF(callbacks_list);
        Py_DECREF(gc_module);
        return;
    }

    if (PyList_Append(callbacks_list, py_callback) != 0) {
        Py_DECREF(py_callback);
        Py_DECREF(callbacks_list);
        Py_DECREF(gc_module);
        return;
    }

    Py_DECREF(callbacks_list);
    Py_DECREF(gc_module);
    *error_message = strdup("Import gc Ok");
}

static void init_tracing_data_array(int count) {
    tracing_data_count = count;
    pytorch_tracing_data_array =
        (TracingData *)malloc(sizeof(TracingData) * tracing_data_count);
    memset(pytorch_tracing_data_array, 0,
           sizeof(TracingData) * tracing_data_count);
}

void systrace_register_tracing(const char **names, int count, char **errors) {
    if (!ensure_python_initialized()) {
        const char *message = "Python runtime symbols unavailable";
        for (int i = 0; i < count; ++i) {
            errors[i] = strdup(message);
        }
        systrace_log_warn("PyTorchTrace", "%s", message);
        return;
    }

    PyGILState_STATE gstate = PyGILState_Ensure();

    init_tracing_data_array(count);

    python_monitoring_enabled = initialize_python_monitoring();
    if (python_monitoring_enabled) {
        systrace_log_info("PyTorchTrace",
                          "Using Python local monitoring for tracing");
    } else {
        systrace_log_info(
            "PyTorchTrace",
            "Python local monitoring unavailable, using profile fallback");
    }

    for (int i = 0; i < count; i++) {
        if (strcmp(names[i], "GC") == 0) {
            systrace_register_gc(errors);
            continue;
        }
        register_tracing_function(names[i], i, errors);
    }

    if (!python_monitoring_enabled)
        set_profiler_for_all_threads();

    PyGILState_Release(gstate);
}
