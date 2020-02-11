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
using namespace std;

namespace stage3 {

void gpu_stage3(const mitm::archive_info &info,
                const mitm_stage2::stage2_candidate &c2, std::vector<keys> &k,
                const mitm::correct_guess *c) {
    for (uint8_t i = 0; i < c2.k20_count; ++i) {
        uint32_t k20 = c2.maybek20[i];
        uint8_t s0 = get_s0(k20);

        for (uint16_t chunk8 = 0; chunk8 < 0x100; ++chunk8) {
            if (c && (chunk8 == c->chunk8)) {
                fprintf(stderr, "On correct chunk8: %02x\n", chunk8);
            }
            // Compute state at the end of first byte
            // Because of the linearity of CRC, k0 calculations
            // can be moved out of the loop and we can just xor in chunk8
            // if we need a little more speed.
            uint32_t crck00 = c2.chunk2 | (c2.chunk6 << 8) | (chunk8 << 16);
            uint32_t k01xf0 = crck00 ^ crc32tab[info.file[0].x[0]];
            uint8_t extra1xf0 = (k01xf0 & 0xff) * CRYPTCONST + 1;
            uint8_t m1xf0 = c2.chunk3 + (extra1xf0 >> 24) + ((c2.cb >> 4) & 1);
            if (m1xf0 != (c2.m1 >> 24)) {
                fprintf(
                    stderr,
                    "Should never happen! m1xf0 = %02x, c2.m1 >> 24 = %02x\n",
                    m1xf0, c2.m1 >> 24);
                exit(-1);
            }
            uint32_t k21xf0 = crc32(k20, m1xf0);
            uint8_t s1xf0 = get_s0(k21xf0);

            uint32_t k01yf0 = crck00 ^ crc32tab[info.file[0].x[0] ^ s0];
            uint8_t extra1yf0 = (k01yf0 & 0xff) * CRYPTCONST;
            uint8_t m1yf0 = c2.chunk3 + (extra1yf0 >> 24) + ((c2.cb >> 5) & 1);
            if (m1yf0 != (c2.m1 & 0xff)) {
                fprintf(
                    stderr,
                    "Should never happen! m1yf0 = %02x, c2.m1 & 0xff = %02x\n",
                    m1xf0, c2.m1 & 0xff);
                exit(-1);
            }
            uint32_t k21yf0 = crc32(k20, m1yf0);
            uint8_t s1yf0 = get_s0(k21yf0);
            if ((info.file[0].x[1] ^ s1xf0 ^ s1yf0) != info.file[0].h[1]) {
                fprintf(stderr,
                        "Should never happen! x[1] = %02x, s1xf0 = %02x, s1yf0 "
                        "= %02x, h[1] = %02x\n",
                        info.file[0].x[1], s1xf0, s1yf0, info.file[0].h[1]);
                exit(-1);
            }

            // Compute state at the end of second byte
            uint32_t k02xf0 = crc32(k01xf0, info.file[0].x[1]);
            uint8_t extra2xf0 = (extra1xf0 + (k02xf0 & 0xff)) * CRYPTCONST + 1;
            uint8_t m2xf0 = c2.chunk7 + (extra2xf0 >> 24) + (c2.cb & 1);
            if (m2xf0 != (c2.m2 >> 24)) {
                fprintf(
                    stderr,
                    "Should never happen! m2xf0 = %02x, c2.m2 >> 24 = %02x\n",
                    m2xf0, c2.m2 >> 24);
                exit(-1);
            }
            uint32_t k22xf0 = crc32(k21xf0, m2xf0);
            uint8_t s2xf0 = get_s0(k22xf0);

            uint32_t k02yf0 = crc32(k01yf0, info.file[0].x[1] ^ s1xf0);
            uint8_t extra2yf0 = (extra1yf0 + (k02yf0 & 0xff)) * CRYPTCONST + 1;
            uint8_t m2yf0 = c2.chunk7 + (extra2yf0 >> 24) + ((c2.cb >> 1) & 1);
            if (m2yf0 != (c2.m2 & 0xff)) {
                fprintf(
                    stderr,
                    "Should never happen! m2yf0 = %02x, c2.m2 & 0xff = %02x\n",
                    m2yf0, c2.m2 & 0xff);
                exit(-1);
            }
            uint32_t k22yf0 = crc32(k21yf0, m2yf0);
            uint8_t s2yf0 = get_s0(k22yf0);
            if ((info.file[0].x[2] ^ s2xf0 ^ s2yf0) != info.file[0].h[2]) {
                fprintf(stderr,
                        "Should never happen! x[2] = %02x, s2xf0 = %02x, s2yf0 "
                        "= %02x, h[2] = %02x\n",
                        info.file[0].x[2], s2xf0, s2yf0, info.file[0].h[2]);
                exit(-1);
            }

            for (uint16_t chunk9 = 0; chunk9 < 0x100; ++chunk9) {
                if (c && (chunk8 == c->chunk8) && (chunk9 == c->chunk9)) {
                    fprintf(stderr, "On correct chunk9: %02x\n", chunk9);
                }
                for (uint8_t cb30 = 0; cb30 < 4; ++cb30) {
                    uint32_t upper = 0x1000000;
                    uint32_t lower = 0x0000000;

                    // Compute state at the end of third byte
                    uint32_t k03xf0 = crc32(k02xf0, info.file[0].x[2]);
                    uint8_t extra3xf0 =
                        (extra2xf0 + (k03xf0 & 0xff)) * CRYPTCONST + 1;
                    uint32_t bound = 0x1000000 - (extra3xf0 & 0xffffff);
                    if (cb30 & 1) {
                        lower = bound > lower ? bound : lower;
                    } else {
                        upper = bound < upper ? bound : upper;
                    }
                    uint8_t m3xf0 = chunk9 + (extra3xf0 >> 24) + (cb30 & 1);
                    uint32_t k23xf0 = crc32(k22xf0, m3xf0);
                    uint8_t s3xf0 = get_s0(k23xf0);

                    uint32_t k03yf0 = crc32(k02yf0, info.file[0].x[2] ^ s2xf0);
                    uint8_t extra3yf0 =
                        (extra2yf0 + (k02yf0 & 0xff)) * CRYPTCONST + 1;
                    bound = 0x1000000 - (extra3yf0 & 0xffffff);
                    if ((cb30 >> 1) & 1) {
                        lower = bound > lower ? bound : lower;
                    } else {
                        upper = bound < upper ? bound : upper;
                    }
                    if (upper < lower) {
                        if (c && (chunk8 == c->chunk8) &&
                            (chunk9 == c->chunk9) &&
                            (cb30 == ((c->carries >> 4) & 3))) {
                            fprintf(
                                stderr,
                                "Failed to use correct guess! Bounds error. "
                                "chunk8 = %02x, chunk9 = %02x, cb30 = %x\n",
                                chunk8, chunk9, cb30);
                        }
                        continue;
                    }
                    uint8_t m3yf0 =
                        chunk9 + (extra3yf0 >> 24) + ((cb30 >> 1) & 1);
                    uint32_t k23yf0 = crc32(k22yf0, m3yf0);
                    uint8_t s3yf0 = get_s0(k23yf0);
                    if ((info.file[0].x[3] ^ s3xf0 ^ s3yf0) !=
                        info.file[0].h[3]) {
                        if (c && (chunk8 == c->chunk8) &&
                            (chunk9 == c->chunk9) &&
                            (cb30 == ((c->carries >> 4) & 3))) {
                            fprintf(stderr,
                                    "Failed to use correct guess! Wrong stream "
                                    "bytes. chunk8 = %02x, chunk9 = %02x, cb30 "
                                    "= %x\n",
                                    chunk8, chunk9, cb30);
                        }
                        continue;
                    }

                    for (uint8_t cb31 = 0; cb31 < 4; ++cb31) {
                        // Do it again for file 1
                        uint32_t k01xf1 = crck00 ^ crc32tab[info.file[1].x[0]];
                        uint8_t extra1xf1 = (k01xf1 & 0xff) * CRYPTCONST + 1;
                        uint8_t m1xf1 =
                            c2.chunk3 + (extra1xf1 >> 24) + ((c2.cb >> 6) & 1);
                        if (m1xf1 != ((c2.m1 >> 8) & 0xff)) {
                            fprintf(stderr,
                                    "Should never happen! m1xf1 = %02x, (c2.m1 "
                                    ">> 8) & 0xff = %02x\n",
                                    m1xf1, (c2.m1 >> 8) & 0xff);
                            exit(-1);
                        }
                        uint32_t k21xf1 = crc32(k20, m1xf1);
                        uint8_t s1xf1 = get_s0(k21xf1);

                        uint32_t k01yf1 =
                            crck00 ^ crc32tab[info.file[1].x[0] ^ s0];
                        uint8_t extra1yf1 = (k01yf1 & 0xff) * CRYPTCONST;
                        uint8_t m1yf1 =
                            c2.chunk3 + (extra1yf1 >> 24) + ((c2.cb >> 7) & 1);
                        if (m1yf1 != ((c2.m1 >> 16) & 0xff)) {
                            fprintf(stderr,
                                    "Should never happen! m1yf1 = %02x, (c2.m1 "
                                    ">> 16) & 0xff = %02x\n",
                                    m1yf1, (c2.m1 >> 16) & 0xff);
                            exit(-1);
                        }
                        uint32_t k21yf1 = crc32(k20, m1yf1);
                        uint8_t s1yf1 = get_s0(k21yf1);
                        if ((info.file[1].x[1] ^ s1xf1 ^ s1yf1) !=
                            info.file[1].h[1]) {
                            fprintf(stderr,
                                    "Should never happen! x[1] = %02x, s1xf1 = "
                                    "%02x, s1yf1 = %02x, h[1] = %02x\n",
                                    info.file[1].x[1], s1xf1, s1yf1,
                                    info.file[1].h[1]);
                            exit(-1);
                        }

                        // Compute state at the end of second byte
                        uint32_t k02xf1 = crc32(k01xf1, info.file[1].x[1]);
                        uint8_t extra2xf1 =
                            (extra1xf1 + (k02xf1 & 0xff)) * CRYPTCONST + 1;
                        uint8_t m2xf1 =
                            c2.chunk7 + (extra2xf1 >> 24) + ((c2.cb >> 2) & 1);
                        if (m2xf1 != (c2.m2 >> 24)) {
                            fprintf(stderr,
                                    "Should never happen! m2xf1 = %02x, c2.m2 "
                                    ">> 24 = %02x\n",
                                    m2xf1, c2.m2 >> 24);
                            exit(-1);
                        }
                        uint32_t k22xf1 = crc32(k21xf1, m2xf1);
                        uint8_t s2xf1 = get_s0(k22xf1);

                        uint32_t k02yf1 =
                            crc32(k01yf1, info.file[1].x[1] ^ s1xf1);
                        uint8_t extra2yf1 =
                            (extra1yf1 + (k02yf1 & 0xff)) * CRYPTCONST + 1;
                        uint8_t m2yf1 =
                            c2.chunk7 + (extra2yf1 >> 24) + ((c2.cb >> 3) & 1);
                        if (m2yf1 != (c2.m2 & 0xff)) {
                            fprintf(stderr,
                                    "Should never happen! m2yf1 = %02x, c2.m2 "
                                    "& 0xff = %02x\n",
                                    m2yf1, c2.m2 & 0xff);
                            exit(-1);
                        }
                        uint32_t k22yf1 = crc32(k21yf1, m2yf1);
                        uint8_t s2yf1 = get_s0(k22yf1);
                        if ((info.file[1].x[2] ^ s2xf1 ^ s2yf1) !=
                            info.file[1].h[2]) {
                            fprintf(stderr,
                                    "Should never happen! x[2] = %02x, s2xf1 = "
                                    "%02x, s2yf1 = %02x, h[2] = %02x\n",
                                    info.file[1].x[2], s2xf1, s2yf1,
                                    info.file[1].h[2]);
                            exit(-1);
                        }

                        // Compute state at the end of third byte
                        uint32_t k03xf1 = crc32(k02xf1, info.file[1].x[2]);
                        uint8_t extra3xf1 =
                            (extra2xf1 + (k03xf1 & 0xff)) * CRYPTCONST + 1;
                        uint8_t m3xf1 = chunk9 + (extra3xf1 >> 24) + (cb31 & 1);
                        bound = 0x1000000 - (extra3xf1 & 0xffffff);
                        if (cb31 & 1) {
                            lower = bound > lower ? bound : lower;
                        } else {
                            upper = bound < upper ? bound : upper;
                        }
                        if (upper < lower) {
                            if (c && (chunk8 == c->chunk8) &&
                                (chunk9 == c->chunk9) &&
                                (cb31 == ((c->carries >> 6) & 3))) {
                                fprintf(stderr,
                                        "Failed to use correct guess! Bounds "
                                        "error. chunk8 = %02x, chunk9 = %02x, "
                                        "cb31 = %x\n",
                                        chunk8, chunk9, cb31);
                            }
                            continue;
                        }
                        uint32_t k23xf1 = crc32(k22xf1, m3xf1);
                        uint8_t s3xf1 = get_s0(k23xf1);

                        uint32_t k03yf1 =
                            crc32(k02yf1, info.file[1].x[2] ^ s2xf1);
                        uint8_t extra3yf1 =
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
                            if (c && (chunk8 == c->chunk8) &&
                                (chunk9 == c->chunk9) &&
                                (cb31 == ((c->carries >> 6) & 3))) {
                                fprintf(stderr,
                                        "Failed to use correct guess! Wrong "
                                        "stream bytes. chunk8 = %02x, chunk9 = "
                                        "%02x, cb31 = %x\n",
                                        chunk8, chunk9, cb31);
                            }
                            continue;
                        }
                        uint32_t k23yf1 = crc32(k22yf1, m3yf1);
                        uint8_t s3yf1 = get_s0(k23yf1);
                        if ((info.file[1].x[3] ^ s3xf1 ^ s3yf1) ==
                            info.file[1].h[3]) {
                            gpu_stage4(info, c2, chunk8, chunk9, cb30, cb31,
                                       crck00, k20, k, c);
                            if (k.size() > 0) {
                                return;
                            }
                        }
                    }
                }
            }
        }
    }
}

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

void gpu_stage4(const mitm::archive_info &info,
                const mitm_stage2::stage2_candidate &c2, const uint16_t chunk8,
                const uint16_t chunk9, const uint8_t cb30, const uint8_t cb31,
                uint32_t crck00, uint32_t k20, std::vector<keys> &k,
                const mitm::correct_guess *c) {
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
                    k0n = crck00 ^ crc32tab[bytes[0]];
                    k1cn = k10;
                    k2n = k20;
                    for (int idx = 0; (idx < 3) && still_good; ++idx) {
                        uint8_t lsbk0n = k0n & 0xff;
                        bound = (bound + lsbk0n) * CRYPTCONST + 1;
                        k1cn = k1cn * CRYPTCONST;
                        uint8_t carry_bit = ((k1cn & 0xffffff) +
                                             (bound & 0xffffff)) > 0x01000000;
                        k2n = crc32(k2n, (k1cn + bound) >> 24);
                        still_good &= (getbits(bits, idx, f, xy) == carry_bit);
                        k0n = crc32(k0n, bytes[idx + 1]);
                    }
                }
            }
            if (still_good) {
                gpu_stages5to10(info, crck00, k10, k20, k, c);
            } else if (is_correct) {
                fprintf(stderr, "Failed to use correct k10!\n");
            }
        }
    }
}

void gpu_stages5to10(const mitm::archive_info &info, const uint32_t crck00,
                     const uint32_t k10, const uint32_t k20,
                     std::vector<keys> &k,
                     const mitm::correct_guess *c) {
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
                k0n = crc32k00 ^ crc32tab[bytes[0]];
                k1cn = k10;
                k2n = k20;
                for (int idx = 0; idx < 10; ++idx) {
                    uint8_t lsbk0n = k0n & 0xff;
                    bound = (bound + lsbk0n) * CRYPTCONST + 1;
                    k1cn = k1cn * CRYPTCONST;
                    k2n = crc32(k2n, (k1cn + bound) >> 24);
                    sn[idx][xy] = get_s0(k2n);
                    k0n = crc32(k0n, bytes[idx + 1]);
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
            keys good = {crc32k00, k10, k20};
            k.push_back(good);
        } else if (is_correct) {
            fprintf(stderr, "Failed to use correct key! chunk10 = %02x\n",
                    chunk10);
        }
    }
}

}  // namespace gpu_stage3

#endif
