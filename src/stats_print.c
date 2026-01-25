// stats_print.c
#include "stats_print.h"
#include "param.h"

static void stats_print_kv(FILE* out, const Stats* s)
{
    fprintf(out, "----------------------------------------\n");
    fprintf(out, "Statistics\n");

#define X_U64(name) fprintf(out, "%s=%" PRIu64 "\n", #name, (uint64_t)s->name);
#define X_DBL(name) fprintf(out, "%s=%.6g\n",        #name, (double)s->name);
#include "stats_fields.def"
#undef X_U64
#undef X_DBL
}

static void stats_print_csv_header(FILE* out)
{
    int first = 1;

#define X_U64(name) do { fprintf(out, "%s%s", first ? "" : ",", #name); first = 0; } while (0)
#define X_DBL(name) do { fprintf(out, "%s%s", first ? "" : ",", #name); first = 0; } while (0)
#include "stats_fields.def"
#undef X_U64
#undef X_DBL

    fputc('\n', out);
}

static void stats_print_csv_values(FILE* out, const Stats* s)
{
    int first = 1;

#define X_U64(name) do { fprintf(out, "%s%" PRIu64, first ? "" : ",", (uint64_t)s->name); first = 0; } while (0)
#define X_DBL(name) do { fprintf(out, "%s%.6g",     first ? "" : ",", (double)s->name);  first = 0; } while (0)
#include "stats_fields.def"
#undef X_U64
#undef X_DBL

    fputc('\n', out);
}

void stats_print(FILE* out,
                 const Stats* s,
                 StatsFormat fmt,
                 int with_csv_header)
{
    if (!out || !s) return;

    switch (fmt) {
    case STATS_FMT_KV:
        stats_print_kv(out, s);
        break;

    case STATS_FMT_CSV:
        if (with_csv_header) stats_print_csv_header(out);
        stats_print_csv_values(out, s);
        break;

    default:
        break;
    }
}

#define STATS_CSV_BUF_SIZE 4096

const char* stats_to_csv_string(const Stats* s)
{
    static char buf[STATS_CSV_BUF_SIZE];
    size_t off = 0;
    int first = 1;

    if (!s) {
        buf[0] = '\0';
        return buf;
    }

#define X_U64(name)                                                         \
    do {                                                                    \
        int n = snprintf(buf + off, STATS_CSV_BUF_SIZE - off,               \
                         "%s%" PRIu64, first ? "" : ",", (uint64_t)s->name);\
        if (n > 0) off += (size_t)n;                                        \
        first = 0;                                                          \
    } while (0)

#define X_DBL(name)                                                         \
    do {                                                                    \
        int n = snprintf(buf + off, STATS_CSV_BUF_SIZE - off,               \
                         "%s%.6g", first ? "" : ",", (double)s->name);     \
        if (n > 0) off += (size_t)n;                                        \
        first = 0;                                                          \
    } while (0)

#include "stats_fields.def"
#undef X_U64
#undef X_DBL

    buf[off < STATS_CSV_BUF_SIZE ? off : STATS_CSV_BUF_SIZE - 1] = '\0';
    return buf;
}


const char* stats_csv_header_to_string(void)
{
    static char buf[STATS_CSV_BUF_SIZE];
    size_t off = 0;
    int first = 1;

#define X_U64(name)                                                         \
    do {                                                                    \
        int n = snprintf(buf + off, STATS_CSV_BUF_SIZE - off,               \
                         "%s%s", first ? "" : ",", #name);                 \
        if (n > 0) off += (size_t)n;                                        \
        first = 0;                                                          \
    } while (0)

#define X_DBL(name)                                                         \
    do {                                                                    \
        int n = snprintf(buf + off, STATS_CSV_BUF_SIZE - off,               \
                         "%s%s", first ? "" : ",", #name);                 \
        if (n > 0) off += (size_t)n;                                        \
        first = 0;                                                          \
    } while (0)

#include "stats_fields.def"
#undef X_U64
#undef X_DBL

    buf[off < STATS_CSV_BUF_SIZE ? off : STATS_CSV_BUF_SIZE - 1] = '\0';
    return buf;
}
