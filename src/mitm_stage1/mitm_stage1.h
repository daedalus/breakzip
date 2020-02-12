#ifndef MITM_STAGE1_H
#define MITM_STAGE1_H

#include <stdio.h>
#include <string.h>
#include <cstdint>
#include <vector>

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

    stage1_candidate() : k20_count(0), chunk2(0), chunk3(0), cb1(0), m1(0) {
        ::memset(maybek20, 0, sizeof(uint32_t) * MAX_K20S);
    };

    stage1_candidate(const stage1_candidate &other)
        : k20_count(other.k20_count),
          chunk2(other.chunk2),
          chunk3(other.chunk3),
          cb1(other.cb1),
          m1(other.m1) {
        ::memset(maybek20, 0, sizeof(uint32_t) * MAX_K20S);
        for (int i = 0; i < k20_count; ++i) {
            maybek20[i] = other.maybek20[i];
        }
    };

    bool operator==(const stage1_candidate &other) {
        if (k20_count == other.k20_count && chunk2 == other.chunk2 &&
            chunk3 == other.chunk3 && cb1 == other.cb1 && m1 == other.m1) {
            for (int i = 0; i < k20_count; ++i) {
                if (maybek20[i] != other.maybek20[i]) {
                    return false;
                }
            }
        }

        return true;
    }
} stage1_candidate;

bool correct_candidate(const mitm::correct_guess &g, const stage1_candidate &c);

void write_stage1_candidate(FILE *f, const stage1_candidate &c);

void read_stage1_candidate(FILE *f, stage1_candidate &c /* output */);

void write_stage1_candidates(const vector<stage1_candidate> &candidates,
                             size_t correct_index = SIZE_MAX /* output */);

void write_stage1_candidate_file(FILE *f,
                                 const vector<stage1_candidate> &candidates,
                                 const size_t start_idx, const size_t num);

void read_stage1_candidates(FILE *f,
                            vector<stage1_candidate> &out /* output */);

void mitm_stage1a(mitm::archive_info &info,
                  std::vector<std::vector<stage1a>> &table,
                  mitm::correct_guess *c = nullptr);

void mitm_stage1b(const mitm::archive_info &info,
                  const std::vector<std::vector<stage1a>> &table,
                  std::vector<stage1_candidate> &candidates, /* output */
                  const mitm::correct_guess *c = nullptr,
                  size_t *correct_candidate_index = nullptr /* output */);

};  // namespace mitm_stage1
#endif
