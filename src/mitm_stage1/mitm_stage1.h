#ifndef MITM_STAGE1_H
#define MITM_STAGE1_H

#include <stdio.h>
#include <cstdint>
#include <vector>
#include <string.h>

#include "mitm_common.h"

namespace mitm_stage1 {

typedef struct stage1a {
    uint8_t s0;
    uint8_t chunk2;
    uint8_t chunk3;
    uint8_t cb;
    uint8_t msbk11xf0;
} stage1a;

typedef struct stage1_candidate {
    static const size_t MAX_K20S = 16;

    // Expect four candidates for chunks 1, 4
    uint32_t maybek20[MAX_K20S];
    uint8_t k20_count;
    uint8_t chunk2;
    uint8_t chunk3;
    uint8_t cb1;
    // The four intermediate bytes.
    // Could recompute, but it's not much more info.
    uint32_t m1;

    stage1_candidate() : k20_count(0), chunk2(0), chunk3(0), cb1(0),
                         m1(0) {
        ::memset(maybek20, 0, sizeof(uint32_t) * MAX_K20S);
    };
} stage1_candidate;

bool correct_candidate(const mitm::correct_guess &g, const stage1_candidate &c);
void write_stage1_candidate(FILE *f, stage1_candidate &c);
void read_stage1_candidate(FILE *f, stage1_candidate &c);
void write_candidates(vector<stage1_candidate> &candidates,
                      size_t correct_index = SIZE_MAX /* output */);
void read_candidates(FILE *f, vector<stage1_candidate>& out /* output */);

void mitm_stage1a(mitm::archive_info& info, std::vector<std::vector<stage1a>>& table,
                  mitm::correct_guess* c = nullptr);

void mitm_stage1b(mitm::archive_info& info, std::vector<std::vector<stage1a>>& table,
                  std::vector<stage1_candidate>& candidates,
                  std::vector<vector<uint16_t>>& preimages,
                  mitm::correct_guess* c = nullptr,
                  size_t *correct_candidate_index = nullptr);

}; // namespace
#endif
