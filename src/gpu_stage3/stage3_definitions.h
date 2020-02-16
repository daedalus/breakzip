/**
 * Copyright (c) 2020, Pyrofex Corporation. All Rights Reserved.
 * Author: Mike Stay <stay@pyrofex.net
 */

#ifndef __STAGE3_DEFINITIONS__
#define __STAGE3_DEFINITIONS__

#include <gflags/gflags.h>
#include <stdio.h>
#include <stdlib.h>

#include "breakzip.h"
#include "stage3.h"

DECLARE_string(output);

using namespace mitm;
using namespace mitm_stage1;
using namespace mitm_stage2;
using namespace std;

namespace stage3 {

CUDA_HOSTDEVICE
void gpu_set_gpu_candidate(mitm_stage2::gpu_stage2_candidate &self,
                           const mitm_stage2::stage2_candidate &other,
                           const int idx) {
    self.maybek20 = other.maybek20[idx];
    self.chunk2 = other.chunk2;
    self.chunk3 = other.chunk3;
    self.chunk6 = other.chunk6;
    self.chunk7 = other.chunk7;
    self.cb = other.cb;
    self.m1 = other.m1;
    self.m2 = other.m2;
}

CUDA_HOSTDEVICE uint8_t gpu_get_s0(uint16_t k20) {
    uint16_t temp = k20 | 3;
    return (temp * (temp ^ 1)) >> 8;
}

#ifdef __CUDACC__
__device__ __constant__
#endif
    const uint32_t gpu_crc32tab[256] = {
        0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f,
        0xe963a535, 0x9e6495a3, 0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
        0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91, 0x1db71064, 0x6ab020f2,
        0xf3b97148, 0x84be41de, 0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
        0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9,
        0xfa0f3d63, 0x8d080df5, 0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
        0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b, 0x35b5a8fa, 0x42b2986c,
        0xdbbbc9d6, 0xacbcf940, 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
        0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423,
        0xcfba9599, 0xb8bda50f, 0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
        0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d, 0x76dc4190, 0x01db7106,
        0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
        0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d,
        0x91646c97, 0xe6635c01, 0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
        0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457, 0x65b0d9c6, 0x12b7e950,
        0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
        0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7,
        0xa4d1c46d, 0xd3d6f4fb, 0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
        0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9, 0x5005713c, 0x270241aa,
        0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
        0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81,
        0xb7bd5c3b, 0xc0ba6cad, 0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
        0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683, 0xe3630b12, 0x94643b84,
        0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
        0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb,
        0x196c3671, 0x6e6b06e7, 0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
        0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5, 0xd6d6a3e8, 0xa1d1937e,
        0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
        0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55,
        0x316e8eef, 0x4669be79, 0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
        0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f, 0xc5ba3bbe, 0xb2bd0b28,
        0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
        0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f,
        0x72076785, 0x05005713, 0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
        0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21, 0x86d3d2d4, 0xf1d4e242,
        0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
        0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69,
        0x616bffd3, 0x166ccf45, 0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
        0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db, 0xaed16a4a, 0xd9d65adc,
        0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
        0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693,
        0x54de5729, 0x23d967bf, 0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
        0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d};

CUDA_HOSTDEVICE uint32_t gpu_crc32(uint32_t x, uint8_t y) {
    return (x >> 8) ^ gpu_crc32tab[y] ^ gpu_crc32tab[x & 0xff];
}

// crcinvtab[(crc32tab[i] >> 3) & 0xff] == i
#ifdef __CUDACC__
__device__ __constant__
#endif
    const uint8_t gpu_crcinvtab[256] = {
        0x00, 0x39, 0x72, 0x4b, 0x7a, 0x43, 0x08, 0x31, 0x6a, 0x53, 0x18, 0x21,
        0x10, 0x29, 0x62, 0x5b, 0x73, 0x4a, 0x01, 0x38, 0x09, 0x30, 0x7b, 0x42,
        0x19, 0x20, 0x6b, 0x52, 0x63, 0x5a, 0x11, 0x28, 0x41, 0x78, 0x33, 0x0a,
        0x3b, 0x02, 0x49, 0x70, 0x2b, 0x12, 0x59, 0x60, 0x51, 0x68, 0x23, 0x1a,
        0x32, 0x0b, 0x40, 0x79, 0x48, 0x71, 0x3a, 0x03, 0x58, 0x61, 0x2a, 0x13,
        0x22, 0x1b, 0x50, 0x69, 0xbb, 0x82, 0xc9, 0xf0, 0xc1, 0xf8, 0xb3, 0x8a,
        0xd1, 0xe8, 0xa3, 0x9a, 0xab, 0x92, 0xd9, 0xe0, 0xc8, 0xf1, 0xba, 0x83,
        0xb2, 0x8b, 0xc0, 0xf9, 0xa2, 0x9b, 0xd0, 0xe9, 0xd8, 0xe1, 0xaa, 0x93,
        0xfa, 0xc3, 0x88, 0xb1, 0x80, 0xb9, 0xf2, 0xcb, 0x90, 0xa9, 0xe2, 0xdb,
        0xea, 0xd3, 0x98, 0xa1, 0x89, 0xb0, 0xfb, 0xc2, 0xf3, 0xca, 0x81, 0xb8,
        0xe3, 0xda, 0x91, 0xa8, 0x99, 0xa0, 0xeb, 0xd2, 0x4f, 0x76, 0x3d, 0x04,
        0x35, 0x0c, 0x47, 0x7e, 0x25, 0x1c, 0x57, 0x6e, 0x5f, 0x66, 0x2d, 0x14,
        0x3c, 0x05, 0x4e, 0x77, 0x46, 0x7f, 0x34, 0x0d, 0x56, 0x6f, 0x24, 0x1d,
        0x2c, 0x15, 0x5e, 0x67, 0x0e, 0x37, 0x7c, 0x45, 0x74, 0x4d, 0x06, 0x3f,
        0x64, 0x5d, 0x16, 0x2f, 0x1e, 0x27, 0x6c, 0x55, 0x7d, 0x44, 0x0f, 0x36,
        0x07, 0x3e, 0x75, 0x4c, 0x17, 0x2e, 0x65, 0x5c, 0x6d, 0x54, 0x1f, 0x26,
        0xf4, 0xcd, 0x86, 0xbf, 0x8e, 0xb7, 0xfc, 0xc5, 0x9e, 0xa7, 0xec, 0xd5,
        0xe4, 0xdd, 0x96, 0xaf, 0x87, 0xbe, 0xf5, 0xcc, 0xfd, 0xc4, 0x8f, 0xb6,
        0xed, 0xd4, 0x9f, 0xa6, 0x97, 0xae, 0xe5, 0xdc, 0xb5, 0x8c, 0xc7, 0xfe,
        0xcf, 0xf6, 0xbd, 0x84, 0xdf, 0xe6, 0xad, 0x94, 0xa5, 0x9c, 0xd7, 0xee,
        0xc6, 0xff, 0xb4, 0x8d, 0xbc, 0x85, 0xce, 0xf7, 0xac, 0x95, 0xde, 0xe7,
        0xd6, 0xef, 0xa4, 0x9d};

CUDA_HOSTDEVICE void gpu_stage3(const mitm::archive_info &info,
                                const mitm_stage2::stage2_candidate &c2,
                                keys *result, const mitm::correct_guess *c) {
    for (uint8_t i = 0; i < c2.k20_count; ++i) {
        mitm_stage2::gpu_stage2_candidate cand;
        gpu_set_gpu_candidate(cand, c2, i);
        gpu_stage3_internal(info, cand, result, c);
        if (result->crck00 != 0 || result->k10 != 0 || result->k20 != 0) {
            return;
        }
    }
}

CUDA_HOSTDEVICE void gpu_stage3_internal(
    const mitm::archive_info &info, const mitm_stage2::gpu_stage2_candidate &c2,
    keys *result, const mitm::correct_guess *c) {
    uint32_t k20 = c2.maybek20;
    uint8_t s0 = gpu_get_s0(k20);

    for (uint16_t chunk8 = 0; chunk8 < 0x100; ++chunk8) {
#ifndef __CUDACC__
        if (c && (chunk8 == c->chunk8)) {
            fprintf(stderr, "On correct chunk8: %02x\n", chunk8);
        }
#endif

        // Compute state at the end of first byte
        // Because of the linearity of CRC, k0 calculations
        // can be moved out of the loop and we can just xor in chunk8
        // if we need a little more speed.
        uint32_t crck00 = c2.chunk2 | (c2.chunk6 << 8) | (chunk8 << 16);
        uint32_t k01xf0 = crck00 ^ gpu_crc32tab[info.file[0].x[0]];
        uint32_t extra1xf0 = (k01xf0 & 0xff) * CRYPTCONST + 1;
        uint8_t m1xf0 = c2.chunk3 + (extra1xf0 >> 24) + ((c2.cb >> 4) & 1);
#ifndef __CUDACC__
        if (m1xf0 != (c2.m1 >> 24)) {
            fprintf(stderr,
                    "Should never happen! m1xf0 = %02x, c2.m1 >> 24 = %02x\n",
                    m1xf0, c2.m1 >> 24);
            exit(-1);
        }
#endif
        uint32_t k21xf0 = gpu_crc32(k20, m1xf0);
        uint8_t s1xf0 = gpu_get_s0(k21xf0);

        uint32_t k01yf0 = crck00 ^ gpu_crc32tab[info.file[0].x[0] ^ s0];
        uint32_t extra1yf0 = (k01yf0 & 0xff) * CRYPTCONST + 1;
        uint8_t m1yf0 = c2.chunk3 + (extra1yf0 >> 24) + ((c2.cb >> 5) & 1);
#ifndef __CUDACC__
        if (m1yf0 != (c2.m1 & 0xff)) {
            fprintf(stderr,
                    "Should never happen! m1yf0 = %02x, c2.m1 & 0xff = %02x\n",
                    m1xf0, c2.m1 & 0xff);
            exit(-1);
        }
#endif

        uint32_t k21yf0 = gpu_crc32(k20, m1yf0);
        uint8_t s1yf0 = gpu_get_s0(k21yf0);

#ifndef __CUDACC__
        if ((info.file[0].x[1] ^ s1xf0 ^ s1yf0) != info.file[0].h[1]) {
            fprintf(stderr,
                    "Should never happen! x[1] = %02x, s1xf0 = %02x, s1yf0 "
                    "= %02x, h[1] = %02x\n",
                    info.file[0].x[1], s1xf0, s1yf0, info.file[0].h[1]);
            exit(-1);
        }
#endif

        // Compute state at the end of second byte
        uint32_t k02xf0 = gpu_crc32(k01xf0, info.file[0].x[1]);
        uint32_t extra2xf0 = (extra1xf0 + (k02xf0 & 0xff)) * CRYPTCONST + 1;
        uint8_t m2xf0 = c2.chunk7 + (extra2xf0 >> 24) + (c2.cb & 1);
#ifndef __CUDACC__
        if (m2xf0 != (c2.m2 >> 24)) {
            fprintf(stderr,
                    "Should never happen! m2xf0 = %02x, c2.m2 >> 24 = %02x\n",
                    m2xf0, c2.m2 >> 24);
            exit(-1);
        }
#endif

        uint32_t k22xf0 = gpu_crc32(k21xf0, m2xf0);
        uint8_t s2xf0 = gpu_get_s0(k22xf0);

        uint32_t k02yf0 = gpu_crc32(k01yf0, info.file[0].x[1] ^ s1xf0);
        uint32_t extra2yf0 = (extra1yf0 + (k02yf0 & 0xff)) * CRYPTCONST + 1;
        uint8_t m2yf0 = c2.chunk7 + (extra2yf0 >> 24) + ((c2.cb >> 1) & 1);
#ifndef __CUDACC__
        if (m2yf0 != (c2.m2 & 0xff)) {
            fprintf(stderr,
                    "Should never happen! m2yf0 = %02x, c2.m2 & 0xff = %02x\n",
                    m2yf0, c2.m2 & 0xff);
            exit(-1);
        }
#endif

        uint32_t k22yf0 = gpu_crc32(k21yf0, m2yf0);
        uint8_t s2yf0 = gpu_get_s0(k22yf0);

#ifndef __CUDACC__
        if ((info.file[0].x[2] ^ s2xf0 ^ s2yf0) != info.file[0].h[2]) {
            fprintf(stderr,
                    "Should never happen! x[2] = %02x, s2xf0 = %02x, s2yf0 "
                    "= %02x, h[2] = %02x\n",
                    info.file[0].x[2], s2xf0, s2yf0, info.file[0].h[2]);
            exit(-1);
        }
#endif

        for (uint16_t chunk9 = 0; chunk9 < 0x100; ++chunk9) {
#ifndef __CUDACC__
            if (c && (chunk8 == c->chunk8) && (chunk9 == c->chunk9)) {
                fprintf(stderr, "On correct chunk9: %02x\n", chunk9);
            }
#endif

            for (uint8_t cb30 = 0; cb30 < 4; ++cb30) {
                uint32_t upper = 0x1000000;
                uint32_t lower = 0x0000000;

                // Compute state at the end of third byte
                uint32_t k03xf0 = gpu_crc32(k02xf0, info.file[0].x[2]);
                uint32_t extra3xf0 =
                    (extra2xf0 + (k03xf0 & 0xff)) * CRYPTCONST + 1;
                uint32_t bound = 0x1000000 - (extra3xf0 & 0xffffff);
                if (cb30 & 1) {
                    lower = bound > lower ? bound : lower;
                } else {
                    upper = bound < upper ? bound : upper;
                }
                uint8_t m3xf0 = chunk9 + (extra3xf0 >> 24) + (cb30 & 1);
                uint32_t k23xf0 = gpu_crc32(k22xf0, m3xf0);
                uint8_t s3xf0 = gpu_get_s0(k23xf0);

                uint32_t k03yf0 = gpu_crc32(k02yf0, info.file[0].x[2] ^ s2xf0);
                uint32_t extra3yf0 =
                    (extra2yf0 + (k02yf0 & 0xff)) * CRYPTCONST + 1;
                bound = 0x1000000 - (extra3yf0 & 0xffffff);
                if ((cb30 >> 1) & 1) {
                    lower = bound > lower ? bound : lower;
                } else {
                    upper = bound < upper ? bound : upper;
                }
                if (upper < lower) {
#ifndef __CUDACC__
                    if (c && (chunk8 == c->chunk8) && (chunk9 == c->chunk9) &&
                        (cb30 == ((c->carries >> 4) & 3))) {
                        fprintf(stderr,
                                "Failed to use correct guess! Bounds error. "
                                "chunk8 = %02x, chunk9 = %02x, cb30 = %x\n",
                                chunk8, chunk9, cb30);
                    }
#endif

                    continue;
                }
                uint8_t m3yf0 = chunk9 + (extra3yf0 >> 24) + ((cb30 >> 1) & 1);
                uint32_t k23yf0 = gpu_crc32(k22yf0, m3yf0);
                uint8_t s3yf0 = gpu_get_s0(k23yf0);

                if ((info.file[0].x[3] ^ s3xf0 ^ s3yf0) != info.file[0].h[3]) {
#ifndef __CUDACC__
                    if (c && (chunk8 == c->chunk8) && (chunk9 == c->chunk9) &&
                        (cb30 == ((c->carries >> 4) & 3))) {
                        fprintf(stderr,
                                "Failed to use correct guess! Wrong stream "
                                "bytes. chunk8 = %02x, chunk9 = %02x, cb30 "
                                "= %x\n",
                                chunk8, chunk9, cb30);
                    }
#endif

                    continue;
                }

                for (uint8_t cb31 = 0; cb31 < 4; ++cb31) {
                    // Do it again for file 1
                    uint32_t k01xf1 = crck00 ^ gpu_crc32tab[info.file[1].x[0]];
                    uint32_t extra1xf1 = (k01xf1 & 0xff) * CRYPTCONST + 1;
                    uint8_t m1xf1 =
                        c2.chunk3 + (extra1xf1 >> 24) + ((c2.cb >> 6) & 1);
#ifndef __CUDACC__
                    if (m1xf1 != ((c2.m1 >> 8) & 0xff)) {
                        fprintf(stderr,
                                "Should never happen! m1xf1 = %02x, (c2.m1 "
                                ">> 8) & 0xff = %02x\n",
                                m1xf1, (c2.m1 >> 8) & 0xff);
                        exit(-1);
                    }
#endif
                    uint32_t k21xf1 = gpu_crc32(k20, m1xf1);
                    uint8_t s1xf1 = gpu_get_s0(k21xf1);

                    uint32_t k01yf1 =
                        crck00 ^ gpu_crc32tab[info.file[1].x[0] ^ s0];
                    uint32_t extra1yf1 = (k01yf1 & 0xff) * CRYPTCONST + 1;
                    uint8_t m1yf1 =
                        c2.chunk3 + (extra1yf1 >> 24) + ((c2.cb >> 7) & 1);
#ifndef __CUDACC__
                    if (m1yf1 != ((c2.m1 >> 16) & 0xff)) {
                        fprintf(stderr,
                                "Should never happen! m1yf1 = %02x, (c2.m1 "
                                ">> 16) & 0xff = %02x\n",
                                m1yf1, (c2.m1 >> 16) & 0xff);
                        exit(-1);
                    }
#endif
                    uint32_t k21yf1 = gpu_crc32(k20, m1yf1);
                    uint8_t s1yf1 = gpu_get_s0(k21yf1);

#ifndef __CUDACC__
                    if ((info.file[1].x[1] ^ s1xf1 ^ s1yf1) !=
                        info.file[1].h[1]) {
                        fprintf(stderr,
                                "Should never happen! x[1] = %02x, s1xf1 = "
                                "%02x, s1yf1 = %02x, h[1] = %02x\n",
                                info.file[1].x[1], s1xf1, s1yf1,
                                info.file[1].h[1]);
                        exit(-1);
                    }
#endif

                    // Compute state at the end of second byte
                    uint32_t k02xf1 = gpu_crc32(k01xf1, info.file[1].x[1]);
                    uint32_t extra2xf1 =
                        (extra1xf1 + (k02xf1 & 0xff)) * CRYPTCONST + 1;
                    uint8_t m2xf1 =
                        c2.chunk7 + (extra2xf1 >> 24) + ((c2.cb >> 2) & 1);
#ifndef __CUDACC__
                    if (m2xf1 != ((c2.m2 >> 8) & 0xff)) {
                        fprintf(stderr,
                                "Should never happen! m2xf1 = %02x, ((c2.m2 >> "
                                "8) & 0xff) = %02x\n",
                                m2xf1, c2.m2 >> 8);
                        exit(-1);
                    }
#endif

                    uint32_t k22xf1 = gpu_crc32(k21xf1, m2xf1);
                    uint8_t s2xf1 = gpu_get_s0(k22xf1);

                    uint32_t k02yf1 =
                        gpu_crc32(k01yf1, info.file[1].x[1] ^ s1xf1);
                    uint32_t extra2yf1 =
                        (extra1yf1 + (k02yf1 & 0xff)) * CRYPTCONST + 1;
                    uint8_t m2yf1 =
                        c2.chunk7 + (extra2yf1 >> 24) + ((c2.cb >> 3) & 1);
#ifndef __CUDACC__
                    if (m2yf1 != ((c2.m2 >> 16) & 0xff)) {
                        fprintf(stderr,
                                "Should never happen! m2yf1 = %02x, ((c2.m2 >> "
                                "16) & 0xff) = %02x\n",
                                m2yf1, ((c2.m2 >> 16) & 0xff));
                        exit(-1);
                    }
#endif

                    uint32_t k22yf1 = gpu_crc32(k21yf1, m2yf1);
                    uint8_t s2yf1 = gpu_get_s0(k22yf1);
#ifndef __CUDACC__
                    if ((info.file[1].x[2] ^ s2xf1 ^ s2yf1) !=
                        info.file[1].h[2]) {
                        fprintf(stderr,
                                "Should never happen! x[2] = %02x, s2xf1 = "
                                "%02x, s2yf1 = %02x, h[2] = %02x\n",
                                info.file[1].x[2], s2xf1, s2yf1,
                                info.file[1].h[2]);
                        exit(-1);
                    }
#endif

                    // Compute state at the end of third byte
                    uint32_t k03xf1 = gpu_crc32(k02xf1, info.file[1].x[2]);
                    uint32_t extra3xf1 =
                        (extra2xf1 + (k03xf1 & 0xff)) * CRYPTCONST + 1;
                    uint8_t m3xf1 = chunk9 + (extra3xf1 >> 24) + (cb31 & 1);
                    bound = 0x1000000 - (extra3xf1 & 0xffffff);
                    if (cb31 & 1) {
                        lower = bound > lower ? bound : lower;
                    } else {
                        upper = bound < upper ? bound : upper;
                    }
                    if (upper < lower) {
#ifndef __CUDACC__
                        if (c && (chunk8 == c->chunk8) &&
                            (chunk9 == c->chunk9) &&
                            (cb31 == ((c->carries >> 6) & 3))) {
                            fprintf(stderr,
                                    "Failed to use correct guess! Bounds "
                                    "error. chunk8 = %02x, chunk9 = %02x, "
                                    "cb31 = %x\n",
                                    chunk8, chunk9, cb31);
                        }
#endif

                        continue;
                    }
                    uint32_t k23xf1 = gpu_crc32(k22xf1, m3xf1);
                    uint8_t s3xf1 = gpu_get_s0(k23xf1);

                    uint32_t k03yf1 =
                        gpu_crc32(k02yf1, info.file[1].x[2] ^ s2xf1);
                    uint32_t extra3yf1 =
                        (extra2yf1 + (k02yf1 & 0xff)) * CRYPTCONST + 1;
                    uint8_t m3yf1 =
                        chunk9 + (extra3yf1 >> 24) + ((cb31 >> 1) & 1);
                    bound = 0x1000000 - (extra3yf1 & 0xffffff);
                    if ((cb31 >> 1) & 1) {
                        lower = bound > lower ? bound : lower;
                    } else {
                        upper = bound < upper ? bound : upper;
                    }
                    if (upper < lower) {
#ifndef __CUDACC__
                        if (c && (chunk8 == c->chunk8) &&
                            (chunk9 == c->chunk9) &&
                            (cb31 == ((c->carries >> 6) & 3))) {
                            fprintf(stderr,
                                    "Failed to use correct guess! Wrong "
                                    "stream bytes. chunk8 = %02x, chunk9 = "
                                    "%02x, cb31 = %x\n",
                                    chunk8, chunk9, cb31);
                        }
#endif

                        continue;
                    }
                    uint32_t k23yf1 = gpu_crc32(k22yf1, m3yf1);
                    uint8_t s3yf1 = gpu_get_s0(k23yf1);

                    if ((info.file[1].x[3] ^ s3xf1 ^ s3yf1) ==
                        info.file[1].h[3]) {
                        gpu_stage4(info, c2, chunk8, chunk9, cb30, cb31, crck00,
                                   k20, result, c);
                        if (result->crck00 != 0 || result->k10 != 0 ||
                            result->k20 != 0) {
                            return;
                        }
                    }
                }
            }
        }
    }
}

#ifdef __CUDACC__
__device__ __constant__
#endif
    int64_t ntable[35][4] = {{-14363699, -11151615, -7227643, 6235929},
                             {-13800186, 4864286, -2714218, 16925678},
                             {-8196160, -13783360, -38464, 8655040},
                             {-7632647, 2232541, 4474961, 19344789},
                             {-6167539, 2631745, -7189179, -2419111},
                             {-5604026, 18647646, -2675754, 8270638},
                             {-2028621, -16415105, 7150715, 11074151},
                             {-1465108, -399204, 11664140, 21763900},
                             {-759020, -6527132, -25324300, 14792900},
                             {-563513, -16015901, -4513425, -10689749},
                             {-195507, 9488769, -20810875, 25482649},
                             {0, 0, 0, 0},
                             {563513, 16015901, 4513425, 10689749},
                             {4138918, -19046850, 14339894, 13493262},
                             {5408519, -9158877, -18135121, 17212011},
                             {5604026, -18647646, 2675754, -8270638},
                             {5972032, 6857024, -13621696, 27901760},
                             {6167539, -2631745, 7189179, 2419111},
                             {6731052, 13384156, 11702604, 13108860},
                             {7437140, 7256228, -25285836, 6137860},
                             {8000653, 23272129, -20772411, 16827609},
                             {11576058, -11790622, -10945942, 19631122},
                             {11771565, -21279391, 9864933, -5851527},
                             {12139571, 4225279, -6432517, 30320871},
                             {12335078, -5263490, 14378358, 4838222},
                             {13041166, -11391418, -22610082, -2132778},
                             {13604679, 4624483, -18096657, 8556971},
                             {14168192, 20640384, -13583232, 19246720},
                             {17743597, -14422367, -3756763, 22050233},
                             {19208705, -14023163, -15420903, 286333},
                             {19772218, 1992738, -10907478, 10976082},
                             {20335731, 18008639, -6394053, 21665831},
                             {25376244, -16654908, -8231724, 2705444},
                             {25939757, -639007, -3718299, 13395193},
                             {26503270, 15376894, 795126, 24084942}};

#define getbits(bits, idx, f, xy) \
    ((bits) >> (((2 - (idx)) * 4) + ((f)*2) + (xy)))

CUDA_HOSTDEVICE
void gpu_stage4(const mitm::archive_info &info,
                const mitm_stage2::gpu_stage2_candidate &c2,
                const uint16_t chunk8, const uint16_t chunk9,
                const uint8_t cb30, const uint8_t cb31, uint32_t crck00,
                uint32_t k20, keys *result, const mitm::correct_guess *c) {
    int64_t msbs[4];
    uint16_t bits = (c2.cb << 4) | (cb30 << 2) | cb31;

    msbs[0] = c2.chunk3 << 24;
    msbs[1] = c2.chunk7 << 24;
    msbs[2] = chunk9 << 24;
    for (uint16_t chunk11 = 0; chunk11 < 0x100; ++chunk11) {
        msbs[3] = chunk11 << 24;
        bool is_correct = false;
        if (c && (chunk8 == c->chunk8) && (chunk9 == c->chunk9) &&
            (cb30 == ((c->carries >> 4) & 3)) &&
            (cb31 == ((c->carries >> 6) & 3)) && (chunk11 == c->chunk11)) {
            is_correct = true;
        }

        // Find values for k10 that give those msbs
        int64_t w[4] = {
            +109 * msbs[0] - 18 * msbs[1] - 125 * msbs[2] + 74 * msbs[3],
            +72 * msbs[0] - 145 * msbs[1] - 60 * msbs[2] - 163 * msbs[3],
            -108 * msbs[0] - 123 * msbs[1] - 19 * msbs[2] + 198 * msbs[3],
            -319 * msbs[0] + 137 * msbs[1] - 245 * msbs[2] - 85 * msbs[3]};

        for (int i = 0; i < 4; ++i) {
            w[i] = -(w[i] & 0x00ffffff);
        }

        int64_t v[4] = {(13604679 * w[0] - 563513 * w[1] - 8196160 * w[2] -
                         6167539 * w[3]) >>
                            32,
                        (4624483 * w[0] - 16015901 * w[1] - 13783360 * w[2] +
                         2631745 * w[3]) >>
                            32,
                        (-18096657 * w[0] - 4513425 * w[1] - 38464 * w[2] -
                         7189179 * w[3]) >>
                            32,
                        (8556971 * w[0] - 10689749 * w[1] + 8655040 * w[2] -
                         2419111 * w[3]) >>
                            32};

        int64_t neighbor[4];
        // Given each k10, check the carry bits we guessed
        for (int n = 0; n < 35; ++n) {
            bool out_of_bounds = false;
            for (int j = 0; j < 4; ++j) {
                neighbor[j] = v[j] + ntable[n][j];
                if (neighbor[j] < 0 || neighbor[j] > 0xffffff) {
                    out_of_bounds = true;
                    break;
                }
            }
            if (out_of_bounds) {
                continue;
            }

            uint32_t k10(uint32_t((neighbor[0] + msbs[0]) * CRYPTCONST_INV));
            bool still_good = true;
            uint32_t k0n, bound, k1cn, k2n;
            for (int f = 0; (f < 2) && still_good; ++f) {
                const uint8_t *bytes = info.file[f].x;
                for (int xy = 0; (xy < 2) && still_good; ++xy) {
                    bound = 0;
                    k0n = crck00 ^ gpu_crc32tab[bytes[0]];
                    k1cn = k10;
                    k2n = k20;
                    for (int idx = 0; (idx < 3) && still_good; ++idx) {
                        uint8_t lsbk0n = k0n & 0xff;
                        bound = (bound + lsbk0n) * CRYPTCONST + 1;
                        k1cn = k1cn * CRYPTCONST;
                        uint8_t carry_bit = ((k1cn & 0xffffff) +
                                             (bound & 0xffffff)) > 0x01000000;
                        k2n = gpu_crc32(k2n, (k1cn + bound) >> 24);
                        still_good &= (getbits(bits, idx, f, xy) == carry_bit);
                        k0n = gpu_crc32(k0n, bytes[idx + 1]);
                    }
                }
            }
            if (still_good) {
                gpu_stages5to10(info, crck00, k10, k20, result, c);
            }  // NV(leaf): notice trailing else if below, please.
#ifndef __CUDACC__
            else if (is_correct) {
                fprintf(stderr, "Failed to use correct k10!\n");
            }
#endif
        }
    }
}

CUDA_HOSTDEVICE
void gpu_stages5to10(const mitm::archive_info &info, const uint32_t crck00,
                     const uint32_t k10, const uint32_t k20, keys *result,
                     const mitm::correct_guess *c) {
    result->crck00 = 0;
    result->k10 = 0;
    result->k20 = 0;
    for (uint16_t chunk10 = 0; chunk10 < 0x100; ++chunk10) {
        bool is_correct = false;
        uint32_t crc32k00 = crck00 | (chunk10 << 24);
        if (c &&
            (crc32k00 == (c->chunk2 | (c->chunk6 << 8) | (c->chunk8 << 16) |
                          (c->chunk10 << 24))) &&
            (k20 == (c->chunk1 | (c->chunk4 << 16) | (c->chunk5 << 24))) &&
            (((k10 * CRYPTCONST) >> 24) == c->chunk3) &&
            (((k10 * CRYPTCONST_POW2) >> 24) == c->chunk7) &&
            (((k10 * CRYPTCONST_POW3) >> 24) == c->chunk9) &&
            (((k10 * CRYPTCONST_POW4) >> 24) == c->chunk11)) {
            is_correct = true;
        }
        bool still_good = true;
        uint32_t k0n, bound, k1cn, k2n;
        for (int f = 0; (f < 2) && still_good; ++f) {
            const uint8_t *bytes = info.file[f].x;
            uint8_t sn[10][2];
            for (int xy = 0; (xy < 2) && still_good; ++xy) {
                bound = 0;
                k0n = crc32k00 ^ gpu_crc32tab[bytes[0]];
                k1cn = k10;
                k2n = k20;
                for (int idx = 0; idx < 10; ++idx) {
                    uint8_t lsbk0n = k0n & 0xff;
                    bound = (bound + lsbk0n) * CRYPTCONST + 1;
                    k1cn = k1cn * CRYPTCONST;
                    k2n = gpu_crc32(k2n, (k1cn + bound) >> 24);
                    sn[idx][xy] = gpu_get_s0(k2n);
                    k0n = gpu_crc32(k0n, bytes[idx + 1]);
                }
            }
            for (int idx = 3; (idx < 10) && still_good; ++idx) {
                if ((info.file[f].x[idx] ^ sn[idx][0] ^ sn[idx][1]) !=
                    info.file[f].h[idx]) {
                    still_good = false;
                    break;
                }
            }
        }
        if (still_good) {
            result->crck00 = crc32k00;
            result->k10 = k10;
            result->k20 = k20;
            return;
        }

#ifndef __CUDACC__
        if (is_correct) {
            fprintf(stderr, "Failed to use correct key! chunk10 = %02x\n",
                    chunk10);
        }
#endif
    }
}

}  // namespace stage3

#endif
