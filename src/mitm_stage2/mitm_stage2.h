#ifndef MITM_STAGE2_H
#define MITM_STAGE2_H

#include <stdio.h>
#include <cstdint>
#include <vector>

#include "crc32.h"
#include "mitm_common.h"
#include "mitm_stage1/mitm_stage1.h"

#ifndef CUDA_HOSTDEVICE
#define CUDA_HOSTDEVICE
#endif

using namespace std;

namespace mitm_stage2 {

typedef struct stage2a {
    uint8_t chunk6;
    uint8_t chunk7;
    uint8_t cb2;
    uint8_t msbk12xf0;
} stage2a;

typedef struct stage2_candidate {
    stage2_candidate()
        : k20_count(0),
          chunk2(0),
          chunk3(0),
          chunk6(0),
          chunk7(0),
          cb(0),
          m1(0),
          m2(0) {}

    struct stage2_candidate& operator=(const struct stage2_candidate& other) {
        for (int i = 0; i < other.k20_count; ++i) {
            this->maybek20[i] = other.maybek20[i];
        }
        this->k20_count = other.k20_count;
        this->chunk2 = other.chunk2;
        this->chunk3 = other.chunk3;
        this->chunk6 = other.chunk6;
        this->chunk7 = other.chunk7;
        this->cb = other.cb;
        this->m1 = other.m1;
        this->m2 = other.m2;
        return *this;
    }

    void print() {
        printf("stage2 candidate:\n  k20_count: %u\n  k20s:\n",
               this->k20_count);
        for (int i = 0; i < this->k20_count; ++i) {
            printf(" %u", this->maybek20[i]);
        }
        printf("\n");
        printf("  chunks: 2: %u 3: %u 6: %u 7: %u cb: %u m1: %u m2: %u",
               this->chunk2, this->chunk3, this->chunk6, this->chunk7, this->cb,
               this->m1, this->m2);
    }

    static const size_t MAX_K20S = 16;

    // Expect four candidates for chunks 1, 4
    uint32_t maybek20[MAX_K20S];
    uint8_t k20_count;
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

typedef struct gpu_stage2_candidate {
    CUDA_HOSTDEVICE gpu_stage2_candidate()
        : maybek20(0),
          chunk2(0),
          chunk3(0),
          chunk6(0),
          chunk7(0),
          cb(0),
          m1(0),
          m2(0) {}

    // Expect four candidates for chunks 1, 4
    uint32_t maybek20;
    uint8_t chunk2;
    uint8_t chunk3;
    uint8_t chunk6;
    uint8_t chunk7;

    uint8_t cb;
    uint8_t padding;
    // The four intermediate bytes.
    // Could recompute, but it's not much more info.
    uint32_t m1;
    uint32_t m2;
} gpu_stage2_candidate;

CUDA_HOSTDEVICE void set_gpu_candidate(
    mitm_stage2::gpu_stage2_candidate& self,
    const mitm_stage2::stage2_candidate& other, const int idx);

void read_stage2_candidate(FILE* f, stage2_candidate& candidate);
void write_stage2_candidate(FILE* f, const stage2_candidate& candidate);

void read_stage2_candidates(stage2_candidate** stage2_candidates /* out */,
                            uint32_t* stage2_candidate_count /* out */);

void read_stage2_candidates_for_gpu(gpu_stage2_candidate** candidates /* out */,
                                    uint32_t* count /* out */);

void write_stage2_candidates(const stage2_candidate* const stage2_candidates,
                             const size_t stage2_candidate_count,
                             const size_t shard_number,
                             const mitm::correct_guess* correct = nullptr);

void mitm_stage2a(mitm::archive_info& info, mitm_stage1::stage1_candidate& c1,
                  std::vector<std::vector<stage2a>>& table,
                  mitm::correct_guess* c = nullptr);
void mitm_stage2b(const mitm::archive_info& info,
                  const mitm_stage1::stage1_candidate& c1,
                  const std::vector<std::vector<stage2a>>& table,
                  stage2_candidate* candidates, /* output */
                  const size_t array_size,
                  size_t& stage2_candidate_count, /* output */
                  const mitm::correct_guess* c = nullptr);

}  // namespace mitm_stage2

#endif
