#include <stdio.h>
#include <stdlib.h>

#include "mitm_stage2.h"

using namespace mitm;
using namespace mitm_stage1;
using namespace std;

// TODO: reverse a and b to have a smaller table
void mitm_stage2a(archive_info& info, stage1_candidate& c1,
                  vector<vector<stage2a>>& table, correct_guess* c) {
    uint8_t cb1 = c1.cb1;
    uint8_t carryx0f0 = cb1 & 1;
    uint8_t carryy0f0 = (cb1 >> 1) & 1;
    uint8_t carryx0f1 = (cb1 >> 2) & 1;
    uint8_t carryy0f1 = (cb1 >> 3) & 1;
    // We always have at least one k20 candidate.
    // All candidates for k20 give the same s0 byte,
    // and all single-step updates of a candidate
    // give the same four s1 bytes
    uint8_t s0 = get_s0(c1.maybek20[0] & 0xffff);
    uint32_t s1xf0 = get_s0(crc32(c1.maybek20[0], c1.m1 >> 24));
    uint32_t s1xf1 = get_s0(crc32(c1.maybek20[0], (c1.m1 >> 8) & 0xff));

    for (uint16_t chunk6 = 0; chunk6 < 0x100; ++chunk6) {
        for (uint16_t chunk7 = 0; chunk7 < 0x100; ++chunk7) {
            for (uint8_t cb2 = 0; cb2 < 0x10; ++cb2) {
                if (chunk6 == c->chunk6 && chunk7 == c->chunk7 &&
                    cb2 == ((c->carries >> 8) & 0xf)) {
                    fprintf(stderr, "Stage 2a, should be on correct guess.\n");
                }
                uint8_t carryx1f0 = cb2 & 1;
                uint8_t carryy1f0 = (cb2 >> 1) & 1;
                uint8_t carryx1f1 = (cb2 >> 2) & 1;
                uint8_t carryy1f1 = (cb2 >> 3) & 1;
                // bounds on low 24 bits of k10 * CRYPTCONST
                uint32_t upper1 = 0x01000000;
                uint32_t lower1 = 0x00000000;
                // bounds on low 24 bits of k10 * CRYPTCONST_POW2
                uint32_t upper2 = 0x01000000;
                uint32_t lower2 = 0x00000000;

                // Compute msbk12s
                uint32_t k0crc = c1.chunk2 | (chunk6 << 8);
                uint32_t extra = 0;
                // TODO: revert double assignment. Added for debugging.
                uint32_t msbxf0 =
                    first_half_step(info.file[0].x[0], false, c1.chunk3,
                                    carryx0f0, k0crc, extra, upper1, lower1);
                msbxf0 =
                    first_half_step(info.file[0].x[1], true, chunk7, carryx1f0,
                                    k0crc, extra, upper2, lower2);
                k0crc = c1.chunk2 | (chunk6 << 8);
                extra = 0;
                uint32_t msbyf0 =
                    first_half_step(info.file[0].x[0] ^ s0, false, c1.chunk3,
                                    carryy0f0, k0crc, extra, upper1, lower1);
                msbyf0 =
                    first_half_step(info.file[0].x[1] ^ s1xf0, true, chunk7,
                                    carryy1f0, k0crc, extra, upper2, lower2);
                if (upper1 < lower1) {
                    fprintf(stderr, "ERROR: Should never happen!\n");
                }
                if (upper2 < lower2) {
                    continue;
                }
                k0crc = c1.chunk2 | (chunk6 << 8);
                extra = 0;
                uint32_t msbxf1 =
                    first_half_step(info.file[1].x[0], false, c1.chunk3,
                                    carryx0f1, k0crc, extra, upper1, lower1);
                msbxf1 =
                    first_half_step(info.file[1].x[1], true, chunk7, carryx1f1,
                                    k0crc, extra, upper2, lower2);
                if (upper1 < lower1) {
                    fprintf(stderr, "ERROR: Should never happen!\n");
                }
                if (upper2 < lower2) {
                    continue;
                }
                k0crc = c1.chunk2 | (chunk6 << 8);
                extra = 0;
                uint32_t msbyf1 =
                    first_half_step(info.file[1].x[0] ^ s0, false, c1.chunk3,
                                    carryy0f1, k0crc, extra, upper1, lower1);
                msbyf1 =
                    first_half_step(info.file[1].x[1] ^ s1xf1, true, chunk7,
                                    carryy1f1, k0crc, extra, upper2, lower2);
                if (upper1 < lower1) {
                    fprintf(stderr, "ERROR: Should never happen!\n");
                }
                if (upper2 < lower2) {
                    continue;
                }
                uint32_t mk = toMapKey(msbxf0, msbyf0, msbxf1, msbyf1);
                stage2a s2a;
                s2a.chunk6 = chunk6;
                s2a.chunk7 = chunk7;
                s2a.cb2 = cb2;
                s2a.msbk12xf0 = msbxf0;
                if (s2a.chunk6 == c->chunk6 && s2a.chunk7 == c->chunk7 &&
                    s2a.cb2 == ((c->carries >> 8) & 0xf)) {
                    fprintf(stderr,
                            "Stage 2a correct. mk = %06x, msbk12xf0 = %02x\n",
                            mk, msbxf0);
                }
                table[mk].push_back(s2a);
            }
        }
    }
}

void mitm_stage2b(archive_info& info, stage1_candidate& c1,
                  vector<vector<stage2a>>& table,
                  vector<stage2_candidate>& candidates,
                  vector<vector<uint16_t>>& preimages, correct_guess* c,
                  bool sample) {
    // Second half of MITM for stage 2
    fprintf(stderr, "Stage 2b\n");
    if (sample) {
        fprintf(stderr, "Correct stage1 candidate\n");
    }

    /*
    If we xor two k22 values together, the result is independent of k20:
    = k22x ^ k22y
    = crc32(k21x, msbk12x) ^ crc32(k21y, msbk12y)
    = crc32(crc32(k20, msbk11x), msbk12x) ^ crc32(crc32(k20, msbk11x), msbk12y)
    = crc32(crc32(k20, msbk11x) ^ crc32(k20, msbk11y), msbk12x ^ msbk12y)
    = crc32(crc32(0, msbk11x ^ msbk11y), msbk12x ^ msbk12y)

    Continuing to expand, the result is the crc of a constant that depends on
    the stage1 candidate with a value from stage 2.
    = crc32(crc32tab[msbk11x ^ msbk11y], msbk12x ^ msbk12y)

    Expanding some more and letting cy = crc32tab[msbk11x ^ msbk11y],
    this is a constant (cy >> 8) depending only on the stage 1 candidate
    xor a crc32tab entry.
    = (cy >> 8) ^ crc32tab[(cy & 0xff) ^ msbk12x ^ msbk12y]
    */
    uint32_t mk1 = c1.m1 ^ ((c1.m1 >> 24) * 0x01010101);
    // Compute the constants from stage1.
    uint32_t cyf0 = crc32tab[mk1 & 0xff];
    uint32_t cxf1 = crc32tab[(mk1 >> 8) & 0xff];
    uint32_t cyf1 = crc32tab[(mk1 >> 16) & 0xff];
    uint32_t cyf0p = (cyf0 >> 10) & 0x3fff;
    uint32_t cxf1p = (cxf1 >> 10) & 0x3fff;
    uint32_t cyf1p = (cyf1 >> 10) & 0x3fff;
    uint32_t cyf0l = cyf0 & 0xff;
    uint32_t cxf1l = cxf1 & 0xff;
    uint32_t cyf1l = cyf1 & 0xff;
    for (uint16_t s2xf0 = 0; s2xf0 < 0x100; ++s2xf0) {
        uint8_t s2yf0 = s2xf0 ^ info.file[0].x[2] ^ info.file[0].h[2];
        for (uint8_t prefix = 0; prefix < 0x40; ++prefix) {
            uint16_t pxf0(preimages[s2xf0][prefix]);

            vector<uint8_t> firsts(0);
            second_half_step(pxf0 ^ cyf0p, s2yf0, firsts, preimages);
            if (!firsts.size()) {
                continue;
            }
            for (uint16_t s2xf1 = 0; s2xf1 < 0x100; ++s2xf1) {
                vector<uint8_t> seconds(0);
                second_half_step(pxf0 ^ cxf1p, s2xf1, seconds, preimages);
                if (!seconds.size()) {
                    continue;
                }
                vector<uint8_t> thirds(0);
                uint8_t s2yf1 = s2xf1 ^ info.file[1].x[2] ^ info.file[0].h[2];
                second_half_step(pxf0 ^ cyf1p, s2yf1, thirds, preimages);
                if (!thirds.size()) {
                    continue;
                }
                for (auto f : firsts) {
                    for (auto s : seconds) {
                        for (auto t : thirds) {
                            uint32_t mapkey((f ^ cyf0l) | ((s ^ cxf1l) << 8) |
                                    ((t ^ cyf1l) << 16));
                            for (auto c2 : table[mapkey]) {
                                stage2_candidate g;

                                for (auto k20 : c1.maybek20) {
                                    uint32_t k21xf0 = crc32(k20, c1.m1 >> 24);
                                    if ((pxf0 & 0x3f) ==
                                            ((crc32(k21xf0, c2.msbk12xf0 >> 24) >>
                                              2) &
                                             0x3f)) {
                                        g.maybek20.push_back(k20);
                                    }
                                }

                                g.chunk2 = c1.chunk2;
                                g.chunk3 = c1.chunk3;
                                g.chunk6 = c2.chunk6;
                                g.chunk7 = c2.chunk7;
                                g.cb = (c1.cb1 << 4) | c2.cb2;
                                g.m1 = c1.m1;
                                g.m2 = mapkey ^ (c2.msbk12xf0 * 0x01010101);

                                if (g.chunk2 == c->chunk2 && g.chunk3 == c->chunk3 &&
                                        g.cb == (c->carries >> 8) && g.chunk6 == c->chunk6 &&
                                        g.chunk7 == c->chunk7) {
                                    fprintf(stderr,
                                            "Pushed back correct candidate!\n");
                                }

                                candidates.push_back(g);
                            }
                        }
                    }
                }
            }
        }
    }
}
