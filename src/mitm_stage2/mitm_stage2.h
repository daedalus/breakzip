#ifndef MITM_STAGE2_H
#define MITM_STAGE2_H

#include <stdio.h>
#include <cstdint>
#include <vector>

#include "crc32.h"
#include "mitm_common.h"
#include "mitm_stage1/mitm_stage1.h"

using namespace std;

namespace mitm_stage2 {

// TODO(stay): Imeplement stage2.

};  // namespace mitm_stage2

typedef struct stage2a {
    uint8_t chunk6;
    uint8_t chunk7;
    uint8_t cb2;
    uint8_t msbk12xf0;
} stage2a;

typedef struct stage2_candidate {
    // Expect four candidates for chunks 1, 4
    vector<uint32_t> maybek20;
    uint8_t chunk2;
    uint8_t chunk3;
    uint8_t chunk6;
    uint8_t chunk7;
    uint8_t cb;
    // The four intermediate bytes.
    // Could recompute, but it's not much more info.
    uint32_t m1;
    uint32_t m2;
} stage2_candidate;

void mitm_stage2a(archive_info& info, stage1_candidate& c1,
                  vector<vector<stage2a>>& table, correct_guess* c = nullptr);
void mitm_stage2b(archive_info& info, stage1_candidate& c1,
                  vector<vector<stage2a>>& table,
                  vector<stage2_candidate>& candidates,
                  vector<vector<uint16_t>>& preimages,
                  correct_guess* c = nullptr,
                  bool sample = false);

#endif
