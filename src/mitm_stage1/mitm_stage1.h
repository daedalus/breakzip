#ifndef MITM_STAGE1_H
#define MITM_STAGE1_H

#include <stdio.h>
#include <cstdint>
#include <vector>

#include "mitm_common.h"

using namespace std;

typedef struct stage1a {
    uint8_t s0;
    uint8_t chunk2;
    uint8_t chunk3;
    uint8_t cb;
    uint8_t msbk11xf0;
} stage1a;

typedef struct stage1_candidate {
    // Expect four candidates for chunks 1, 4
    vector<uint32_t> maybek20;
    uint8_t chunk2;
    uint8_t chunk3;
    uint8_t cb1;
    // The four intermediate bytes.
    // Could recompute, but it's not much more info.
    uint32_t m1;
} stage1_candidate;

void mitm_stage1a(archive_info& info, vector<vector<stage1a>>& table,
                  correct_guess* c = nullptr);

void mitm_stage1b(archive_info& info, vector<vector<stage1a>>& table,
                  vector<stage1_candidate>& candidates,
                  vector<vector<uint16_t>>& preimages,
                  correct_guess* c = nullptr);

#endif
