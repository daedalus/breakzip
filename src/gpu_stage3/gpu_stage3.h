#ifndef GPU_STAGE3_H
#define GPU_STAGE3_H

#include <stdio.h>
#include <cstdint>
#include <vector>

#include "breakzip.h"

using namespace std;

namespace gpu_stage3 {

typedef struct keys {
    uint32_t crck00, k10, k20;
} keys;

void gpu_stage3(const mitm::archive_info &info,
                const mitm_stage2::stage2_candidate &c2,
                /* output */ std::vector<keys> &k,
                const mitm::correct_guess *c = nullptr);

void gpu_stage4(const mitm::archive_info &info,
                const mitm_stage2::stage2_candidate &c2, const uint16_t chunk8,
                const uint16_t chunk9, const uint8_t cb30, const uint8_t cb31,
                uint32_t crck00, uint32_t k20,
                /* output */ std::vector<keys> &k,
                const mitm::correct_guess *c = nullptr);

void gpu_stages5to10(const mitm::archive_info &info, const uint32_t crck00,
                     const uint32_t k10, const uint32_t k20,
                     /* output */ std::vector<gpu_stage3::keys> &k,
                     const mitm::correct_guess *c = nullptr);

};  // namespace gpu_stage3

#endif
