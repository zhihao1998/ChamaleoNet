// stats.h
#pragma once
#include <stdint.h>
#include <stdio.h>
#include <inttypes.h>
#include "param.h"

typedef struct Stats
{
#define X_U64(name) uint64_t name;
#define X_DBL(name) double   name;
#include "stats_fields.def"
#undef X_U64
#undef X_DBL
} Stats;

typedef enum
{
    STATS_FMT_KV  = 0, // name=value
    STATS_FMT_CSV = 1  // CSV
} StatsFormat;

void stats_print(FILE *out,
                 const Stats *s,
                 StatsFormat fmt,
                 int with_csv_header);

const char* stats_to_csv_string(const Stats* s);
const char* stats_csv_header_to_string(void);