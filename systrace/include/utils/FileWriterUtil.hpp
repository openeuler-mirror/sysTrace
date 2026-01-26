#pragma once

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>

#ifndef NSEC_PER_USEC
const int NSEC_PER_USEC = 1000;
#endif

#ifndef ERR_TP_NO_BUFF
const int ERR_TP_NO_BUFF = 1;
#endif

namespace systrace {
namespace fileWriterUtil {

typedef struct {
    char *buf;
    size_t total_size;
    size_t used_size;
    size_t chunk_size;
    FILE *fp;
    std::string id;
} strbuf_t;

static inline void strbuf_init(strbuf_t *sb, size_t chunk_size, FILE *fp,
                               const std::string &id = "") {
    if (!sb)
        return;

    sb->total_size = chunk_size;
    sb->used_size = 0;
    sb->chunk_size = chunk_size;
    sb->fp = fp;
    sb->id = id;
    sb->buf = static_cast<char *>(malloc(sb->total_size));

    if (sb->buf) {
        memset(sb->buf, 0, sb->total_size);
    } else {
        std::cerr << "[" << sb->id
                  << "] Allocate buffer failed, size: " << chunk_size
                  << std::endl;
    }
}

static inline void strbuf_update_offset(strbuf_t *sb, int written_len) {
    if (sb && sb->buf && written_len > 0) {
        sb->used_size += written_len;
    }
}

static inline int strbuf_flush(strbuf_t *sb) {
    if (!sb || !sb->buf || !sb->fp || sb->used_size == 0) {
        return 0;
    }

    size_t ret = fwrite(sb->buf, 1, sb->used_size, sb->fp);
    if (ret != sb->used_size) {
        std::cerr << "[" << sb->id << "] Flush buffer failed, written: " << ret
                  << " expected: " << sb->used_size << std::endl;
        return -1;
    }

    memset(sb->buf, 0, sb->total_size);
    sb->used_size = 0;
    return 0;
}

static inline void strbuf_destroy(strbuf_t *sb) {
    if (!sb)
        return;

    if (sb->used_size > 0) {
        strbuf_flush(sb);
    }

    if (sb->buf) {
        free(sb->buf);
        sb->buf = nullptr;
    }

    sb->total_size = 0;
    sb->used_size = 0;
    sb->chunk_size = 0;
    sb->fp = nullptr;
    sb->id.clear();
}

static inline bool strbuf_check_space(strbuf_t *sb, size_t need_size = 256) {
    if (!sb || !sb->buf)
        return false;

    size_t remaining = sb->total_size - sb->used_size;
    if (remaining < need_size) {
        if (strbuf_flush(sb) != 0) {
            return false;
        }
    }
    return true;
}

} // namespace fileWriterUtil
} // namespace systrace