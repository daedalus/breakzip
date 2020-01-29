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
    stage2_candidate() : k20_count(0), chunk2(0), chunk3(0), chunk6(0),
                         chunk7(0), cb(0), m1(0), m2(0) {
        ::memset(maybek20, 0, MAX_K20S * sizeof(uint32_t));
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

void mitm_stage2a(mitm::archive_info& info, mitm_stage1::stage1_candidate& c1,
                  std::vector<std::vector<stage2a>>& table,
                  mitm::correct_guess* c = nullptr);
void mitm_stage2b(const mitm::archive_info& info,
                  const mitm_stage1::stage1_candidate& c1,
                  const std::vector<std::vector<stage2a>>& table,
                  std::vector<stage2_candidate>& candidates, /* output */
                  const std::vector<std::vector<uint16_t>>& preimages,
                  const mitm::correct_guess* c = nullptr,
                  const bool sample = false);

#endif
