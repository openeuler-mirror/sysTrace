add_definitions(-DSYSTRACE_EXPORTS -D_GLIBCXX_USE_CXX11_ABI=1)

set(PYTHON_TRACING_SOURCES
    python/pytorch_tracing_loader.cc
    python/pytorch_tracing_manager.cc
)

set_source_files_properties(
    systrace_manager.cc
    library_loader.cc
    ${PYTHON_TRACING_SOURCES}
    PROPERTIES COMPILE_FLAGS "-fPIC -Wall -Wextra"
)