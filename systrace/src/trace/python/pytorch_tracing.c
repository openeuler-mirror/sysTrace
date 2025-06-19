#include "pytorch_tracing.h"
#if PY_MAJOR_VERSION >= 3 && PY_MINOR_VERSION >= 11
#include <pyframe.h>
#endif

Stagetype determine_stage_type(const char *function_name)
{
    if (function_name == NULL)
    {
        return UNKNOWN;
    }

    if (strcmp(function_name, "GC") == 0)
    {
        return GC;
    }
    if (strcmp(function_name,
               "torch.utils.data.dataloader@_BaseDataLoaderIter@__next__") == 0)
    {
        return DATALOADER;
    }
    if (strcmp(function_name, "torch_npu@npu@synchronize") == 0 ||
        strcmp(function_name, "torch_npu.npu@Event@synchronize") == 0 ||
        strcmp(function_name, "torch_npu.npu@Event@wait") == 0 ||
        strcmp(function_name, "torch_npu.npu@Stream@synchronize") == 0 ||
        strcmp(function_name, "torch_npu.npu@Stream@wait_event") == 0 ||
        strcmp(function_name, "torch_npu.npu@Stream@wait_stream") == 0)
    {
        return SYNCHRONIZATION;
    }
    if (strcmp(function_name, "torch@autograd@backward") == 0 ||
        strcmp(function_name, "torch@autograd@grad") == 0)
    {
        return BACKWARD;
    }
    if (strcmp(function_name,
               "megatron.core.pipeline_parallel@schedules@forward_step") == 0)
    {
        return FORWARD;
    }
    if (strcmp(function_name,
               "megatron.core.pipeline_parallel@schedules@backward_step") == 0)
    {
        return BACKWARD;
    }
    return UNKNOWN;
}

static int register_tracing_function(const char *name, int index, char **errors)
{
    int64_t code_address;
    int is_native;
    int ret =
        GetFuncAddressByPython(name, errors + index, &code_address, &is_native);

    if (ret)
    {
        printf("register function `%s` error\n", name);
        return ret;
    }

    printf("register function `%s` at address %ld\n", name, code_address);
    addTracingData(index, name);

    TracingFunction *traced_function =
        (TracingFunction *)malloc(sizeof(TracingFunction));
    traced_function->tag_name = index;
    traced_function->function_name = strdup(name);
    traced_function->py_code_address = code_address;
    traced_function->is_native = is_native;

    HASH_ADD(hh, pytorch_tracing_func_map, py_code_address, sizeof(int64_t),
             traced_function);

    return 0;
}

static void set_profiler_for_all_threads()
{
    PyEval_SetProfile(profiler, NULL);

    PyThreadState *tstate = PyThreadState_Get();
    PyThreadState *thread_array[PY_TRACING_MAX_THREADS];
    memset(thread_array, 0, sizeof(thread_array));

    int thread_count = 0;
    while (tstate != NULL && thread_count < PY_TRACING_MAX_THREADS)
    {
        thread_array[thread_count++] = tstate;
        printf("Set profiler for thread %ld\n", tstate->thread_id);
        tstate = PyThreadState_Next(tstate);
    }

    for (int i = 0; i < thread_count; i++)
    {
        PyThreadState_Swap(thread_array[i]);
        PyEval_SetProfile(profiler, NULL);
    }

    PyThreadState_Swap(thread_array[0]);
}

#if PY_MAJOR_VERSION >= 3 && PY_MINOR_VERSION >= 11
static void capture_stack(PyFrameObject *frame, PyTorchTracingData *trace_entry)
{
    PyGILState_STATE gstate = PyGILState_Ensure();
    int depth = 0;
    while (frame && depth < MAX_STACK_DEPTH)
    {
        PyCodeObject *code = PyFrame_GetCode(frame);
        if (!code)
        {
            break;
        }

        const char *name = PyUnicode_AsUTF8(code->co_name);
        const char *file = PyUnicode_AsUTF8(code->co_filename);
        int line = PyFrame_GetLineNumber(frame);

        snprintf(trace_entry->stack_info[depth], 256, "%s@%s:%d",
                 name ? name : "unknown", file ? file : "unknown", line);

        PyFrameObject *next_frame = PyFrame_GetBack(frame);
        Py_DECREF(code);
        frame = next_frame;

        depth++;
    }
    trace_entry->stack_depth = depth;
    PyGILState_Release(gstate);
}

uint64_t getCodeOfFrame(PyFrameObject *frame)
{
    return (int64_t)(uintptr_t)PyFrame_GetCode(frame);
}
#else
static void capture_stack(PyFrameObject *frame, PyTorchTracingData *trace_entry)
{
    PyGILState_STATE gstate = PyGILState_Ensure();
    int depth = 0;
    while (frame && depth < MAX_STACK_DEPTH)
    {
        snprintf(trace_entry->stack_info[depth], 256, "%s@%s:%d",
                 PyUnicode_AsUTF8(frame->f_code->co_name),
                 PyUnicode_AsUTF8(frame->f_code->co_filename),
                 PyFrame_GetLineNumber(frame));
        frame = frame->f_back;
        depth++;
    }
    trace_entry->stack_depth = depth;
    PyGILState_Release(gstate);
}

uint64_t getCodeOfFrame(PyFrameObject *frame)
{
    return (int64_t)(uintptr_t)(frame->f_code);
}

#endif

uint64_t getMsTime()
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000 + (uint64_t)tv.tv_usec;
}

static void ensure_python_initialized()
{
    if (!Py_IsInitialized())
    {
        Py_Initialize();
    }
}

TracingFunction *isTracedPyTorchFunction(PyFrameObject *frame)
{
    uint64_t code_address = getCodeOfFrame(frame);
    TracingFunction *traced_function = NULL;
    HASH_FIND(hh, pytorch_tracing_func_map, &code_address, sizeof(int64_t),
              traced_function);
    return traced_function;
}

static int profiler(PyObject *obj, PyFrameObject *frame, int what,
                    PyObject *arg)
{
    TracingFunction *func_data = isTracedPyTorchFunction(frame);
    if (!func_data)
        return 0;
    int tag_name = func_data->tag_name;
    int stage_type = determine_stage_type(func_data->function_name);
    if ((what == PyTrace_CALL) && start_tracing)
    {
        pthread_mutex_lock(&mutex);
        TracingData *tracing_data = receiveTracingData(tag_name);
        PyTorchTracingDataArray *curr_data = tracing_data->curr_data;
        if (curr_data->cur == PY_TRACING_BUFFER_SIZE)
        {
            systrace_return_pytorch_tracing_data_array(
                curr_data, PY_TRACING_READY_POOL, tag_name);
            tracing_data->curr_data =
                systrace_get_empty_pytorch_tracing_data_array(tag_name);
            curr_data = tracing_data->curr_data;
        }
        curr_data->data[curr_data->cur].start = getMsTime();
        if (stage_type == DATALOADER)
        {
            global_stage_id++;
        }
        curr_data->data[curr_data->cur].stage_id = global_stage_id;
        curr_data->data[curr_data->cur].stage_type = stage_type;
        global_stage_type = stage_type;
        capture_stack(frame, &curr_data->data[curr_data->cur]);

        pthread_mutex_unlock(&mutex);
    }
    else if (what == PyTrace_RETURN)
    {
        pthread_mutex_lock(&mutex);
        TracingData *tracing_data = receiveTracingData(tag_name);
        if (start_tracing)
        {
            PyTorchTracingDataArray *curr_data = tracing_data->curr_data;
            curr_data->data[curr_data->cur].count = tracing_data->count;
            curr_data->data[curr_data->cur++].end = getMsTime();
        }
        tracing_data->count++;
        pthread_mutex_unlock(&mutex);
    }
    return 0;
}

static int set_error_message(char **error_message, const char *format, ...) {
    va_list args;
    va_start(args, format);
    int size = vsnprintf(NULL, 0, format, args) + 1;
    va_end(args);
    
    *error_message = malloc(size);
    if (!*error_message) return 0;
    
    va_start(args, format);
    vsnprintf(*error_message, size, format, args);
    va_end(args);
    
    return 1;
}

static int parse_input_string(const char *code, char ***tokens, int *token_count) {
    char *copy = strdup(code);
    if (!copy) return 0;
    
    char *saveptr = NULL;
    *token_count = 0;
    *tokens = malloc(3 * sizeof(char*));
    if (!*tokens) {
        free(copy);
        return 0;
    }
    
    for (char *token = strtok_r(copy, "@", &saveptr); 
         token && *token_count < 3; 
         token = strtok_r(NULL, "@", &saveptr)) {
        (*tokens)[(*token_count)++] = strdup(token);
    }
    
    free(copy);
    return 1;
}

static char* build_python_code(const char *code, char **tokens, int token_count) {
    const char *template = 
        "try:\n"
        "    obj = None\n"
        "%s\n"
        "    while hasattr(obj, '__wrapped__'):\n"
        "        obj = getattr(obj, '__wrapped__')\n"
        "    if hasattr(obj, '__code__'):\n"
        "        address = id(obj.__code__)\n"
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
        asprintf(&import_part, 
            "    from %s import %s as obj", 
            tokens[0], tokens[1]);
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
                              int64_t *address, int *is_native, char **error_message) {
    PyObject *globals = use_globals ? PyEval_GetGlobals() : PyDict_New();
    PyObject *locals = PyDict_New();
    
    if (!globals || !locals) {
        if (!use_globals && globals) Py_DECREF(globals);
        if (locals) Py_DECREF(locals);
        return set_error_message(error_message, "Failed to create Python dictionaries");
    }
    
    PyObject *result = PyRun_String(python_code, Py_file_input, globals, locals);
    if (!result) {
        PyObject *ptype, *pvalue, *ptraceback;
        PyErr_Fetch(&ptype, &pvalue, &ptraceback);
        PyErr_NormalizeException(&ptype, &pvalue, &ptraceback);
        
        if (pvalue) {
            PyObject *py_str = PyObject_Str(pvalue);
            if (py_str) {
                const char *str_error = PyUnicode_AsUTF8(py_str);
                set_error_message(error_message, "Python error: %s", str_error ? str_error : "Unknown error");
                Py_DECREF(py_str);
            }
        }
        
        Py_XDECREF(ptype);
        Py_XDECREF(pvalue);
        Py_XDECREF(ptraceback);
        PyErr_Clear();
        
        if (!use_globals) Py_DECREF(globals);
        Py_DECREF(locals);
        return 1;
    }
    Py_DECREF(result);
    
    PyObject *py_address = PyDict_GetItemString(locals, "address");
    PyObject *py_is_native = PyDict_GetItemString(locals, "is_native");
    
    if (!py_address || !py_is_native) {
        if (!use_globals) Py_DECREF(globals);
        Py_DECREF(locals);
        return set_error_message(error_message, "Failed to get address or is_native from execution");
    }
    
    *address = PyLong_AsLongLong(py_address);
    *is_native = PyLong_AsLongLong(py_is_native);
    
    if (!use_globals) Py_DECREF(globals);
    Py_DECREF(locals);
    return 0;
}

static int GetFuncAddressByPython(const char *code, char **error_message,
                         int64_t *address, int *is_native) {
    *error_message = NULL;
    *address = 0;
    *is_native = 0;
    
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
        for (int i = 0; i < token_count; i++) free(tokens[i]);
        free(tokens);
        return set_error_message(error_message, "Failed to build Python code");
    }
    
    int use_globals = (token_count == 0);
    int result = execute_python_code(python_code, use_globals, address, is_native, error_message);
    
    free(python_code);
    for (int i = 0; i < token_count; i++) free(tokens[i]);
    free(tokens);
    
    if (result == 0) {
        set_error_message(error_message, "Get __code__ attribute for '%s' OK", code);
    }
    
    return result;
}
static TracingData *receiveTracingData(int name)
{
    return pytorch_tracing_data_array + name;
}

static void addTracingData(int name, const char *func_name)
{
    TracingData *v = receiveTracingData(name);
    v->tag_name = name;
    v->curr_data = systrace_get_empty_pytorch_tracing_data_array(name);
    v->function_name = strdup(func_name);
}

static void getGcInfo(PyTorchTracingData *data, PyObject *info)
{
    if (!PyDict_Check(info))
        return;
    PyObject *collected = PyDict_GetItemString(info, "collected");
    PyObject *uncollectable = PyDict_GetItemString(info, "uncollectable");

    if (collected && PyLong_Check(collected))
    {
        data->payload.gc_debug[0] = PyLong_AsLong(collected);
    }
    else
    {
        data->payload.gc_debug[0] = -1;
    }

    if (uncollectable && PyLong_Check(uncollectable))
    {
        data->payload.gc_debug[1] = PyLong_AsLong(uncollectable);
    }
    else
    {
        data->payload.gc_debug[1] = -1;
    }
}

static void gcCallback(PyObject *phase, PyObject *info)
{
    pthread_mutex_lock(&mutex);
    if (PyUnicode_CompareWithASCIIString(phase, "start") == 0 && start_tracing)
    {
        TracingData *tracing_data = receiveTracingData(PY_TRACING_GC);
        PyTorchTracingDataArray *curr_data = tracing_data->curr_data;
        if (curr_data->cur == PY_TRACING_BUFFER_SIZE)
        {
            systrace_return_pytorch_tracing_data_array(
                curr_data, PY_TRACING_READY_POOL, PY_TRACING_GC);
            tracing_data->curr_data =
                systrace_get_empty_pytorch_tracing_data_array(PY_TRACING_GC);
            curr_data = tracing_data->curr_data;
        }
        curr_data->data[curr_data->cur].start = getMsTime();
        pthread_mutex_unlock(&mutex);
    }
    else if (PyUnicode_CompareWithASCIIString(phase, "stop") == 0)
    {
        TracingData *tracing_data = receiveTracingData(PY_TRACING_GC);
        if (start_tracing)
        {
            PyTorchTracingDataArray *curr_data = tracing_data->curr_data;
            if (start_tracing)
            {
                curr_data->data[curr_data->cur].count = tracing_data->count;
                curr_data->data[curr_data->cur].type = PAYLOAD_GC;
                getGcInfo(curr_data->data + curr_data->cur, info);
                curr_data->data[curr_data->cur++].end = getMsTime();
            }
            curr_data->data[curr_data->cur].count = tracing_data->count;
            curr_data->data[curr_data->cur].stage_id = global_stage_id;
            curr_data->data[curr_data->cur++].end = getMsTime();
        }
        tracing_data->count++;
    }
    pthread_mutex_unlock(&mutex);
}

static PyObject *gcCallbackWrapper(PyObject *self, PyObject *args,
                                   PyObject *kwargs)
{
    PyObject *phase, *info;
    if (!PyArg_ParseTuple(args, "OO", &phase, &info))
    {
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
systrace_get_partial_pytorch_tracing_data_array(int name)
{
    pthread_mutex_lock(&mutex);
    TracingData *tracing_data = receiveTracingData(name);
    if ((!tracing_data || !tracing_data->curr_data) ||
        (tracing_data->curr_data->cur == 0))
    {
        pthread_mutex_unlock(&mutex);
        return NULL;
    }
    PyTorchTracingDataArray *result = tracing_data->curr_data;
    tracing_data->curr_data =
        systrace_get_empty_pytorch_tracing_data_array(name);
    pthread_mutex_unlock(&mutex);
    return result;
}

void systrace_register_gc(char **error_message)
{
    addTracingData(PY_TRACING_GC, "GC");
    PyObject *gc_module = PyImport_ImportModule("gc");
    if (!gc_module)
    {
        return;
    }

    PyObject *callbacks_list = PyObject_GetAttrString(gc_module, "callbacks");
    if (!callbacks_list || !PyList_Check(callbacks_list))
    {
        Py_XDECREF(callbacks_list);
        Py_DECREF(gc_module);
        return;
    }

    PyObject *py_callback = PyObject_New(PyObject, &GcCallbackType);

    if (!py_callback)
    {
        Py_DECREF(callbacks_list);
        Py_DECREF(gc_module);
        return;
    }

    if (PyList_Append(callbacks_list, py_callback) != 0)
    {
        Py_DECREF(py_callback);
        Py_DECREF(callbacks_list);
        Py_DECREF(gc_module);
        return;
    }

    Py_DECREF(callbacks_list);
    Py_DECREF(gc_module);
    *error_message = strdup("Import gc Ok");
}

static void init_tracing_data_array(int count)
{
    tracing_data_count = count;
    pytorch_tracing_data_array =
        (TracingData *)malloc(sizeof(TracingData) * tracing_data_count);
    memset(pytorch_tracing_data_array, 0,
           sizeof(TracingData) * tracing_data_count);
}

void systrace_register_tracing(const char **names, int count, char **errors)
{
    ensure_python_initialized();

    PyGILState_STATE gstate = PyGILState_Ensure();

    init_tracing_data_array(count);

    for (int i = 0; i < count; i++)
    {
        if (strcmp(names[i], "GC") == 0)
        {
            systrace_register_gc(errors);
            continue;
        }
        register_tracing_function(names[i], i, errors);
    }

    set_profiler_for_all_threads();

    PyGILState_Release(gstate);
}