ELASTICML_ENABLE_METRICS_KEY = "ELASTICML_ENABLE_METRICS"
ELASTICML_METRICSDIR_KEY = "ELASTICML_METRICS_DIR"
DEFAULT_METRICS_DIR_VAL = "/tmp/elastic_ml_training_metrics"
ENABLE_DIST_COLLECTION_KEY = "ELASTICML_ENABLE_DIST_COLLECTION"
ENABLE_DIST_SHAPE_COLLECTION_KEY = "ELASTICML_ENABLE_DIST_SHAPE_COLLECTION"
ENABLE_CSV_METRICS_KEY = "ELASTICML_ENABLE_CSV_METRICS"
ENABLE_PROM_METRICS_KEY = "ELASTICML_ENABLE_PROM_METRICS"
ELASTICML_JOB_ID = "ELASTICML_JOB_ID"
ENABLE_DIST_TRACEBACK_COLLECTION_KEY = "ELASTICML_ENABLE_DIST_TRACEBACK"

STEP_HEADERS = [
    "time","host","global_rank","custom_tag",
    "host_enter_time","num_step",
    "is_fw","is_bw","is_e2e"
]

COMM_HEADERS = [
    "time","host","global_rank","src_rank","dst_rank",
    "op","input_dtype","input_shape","output_dtype","output_shape",
    "host_enter_time","task_start_time",
    "custom_tag","async_op"
]