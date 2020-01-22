#include <stdio.h>
#include <stdlib.h>

#include "crc32.h"
#include "mitm_stage1.h"

void build_preimages(vector<vector<uint16_t>> &preimages) {
    // Build preimage lookup table
    for (uint16_t k20 = 0; k20 < 0x4000; ++k20) {
        uint16_t temp = (k20 << 2) | 3;
        uint8_t s = ((temp * (temp ^ 1)) >> 8) & 0xff;
        preimages[s].push_back(k20);
    }
}

uint8_t get_s0(uint16_t k20) {
    uint16_t temp = k20 | 3;
    return (temp * (temp ^ 1)) >> 8;
}

correct_guess correct(archive_info info) {
    correct_guess result;

    const uint32_t k00 = info.key[0];
    const uint32_t k10 = info.key[1];
    const uint32_t k20 = info.key[2];
    const uint32_t crc32k00 = crc32(k00, 0);

    result.chunk2 = (crc32k00 >> 0) & 0xff;
    result.chunk6 = (crc32k00 >> 8) & 0xff;
    result.chunk8 = (crc32k00 >> 16) & 0xff;
    result.chunk10 = (crc32k00 >> 24) & 0xff;

    result.chunk3 = (k10 * CRYPTCONST) >> 24;
    result.chunk7 = (k10 * CRYPTCONST_POW2) >> 24;
    result.chunk9 = (k10 * CRYPTCONST_POW3) >> 24;
    result.chunk11 = (k10 * CRYPTCONST_POW4) >> 24;

    result.chunk1 = k20 & 0xffff;
    result.chunk4 = (k20 >> 16) & 0xff;
    result.chunk5 = k20 >> 24;

    for (int f = 0; f < 2; ++f) {
        for (int s = 0; s < 4; ++s) {
            result.sx[f][s] = info.file[f].x[s] ^ info.file[f].y[s];
        }
    }

    uint16_t bits = 0;
    for (int f = 0; f < 2; ++f) {
        for (int xy = 0; xy < 2; ++xy) {
            const uint8_t *bytes = xy ? info.file[f].y : info.file[f].x;
            const uint8_t *encrypted = xy ? info.file[f].h : info.file[f].y;
            uint32_t bound = 0;
            uint32_t k0n = k00;
            uint32_t k1cn = k10;
            uint32_t k1 = k10;
            uint32_t k2n = k20;
            uint8_t sn = get_s0(k20 & 0xffff);
            // stage_1 should be thought of as "stage - 1"
            for (int stage_1 = 0; stage_1 < 4; ++stage_1) {
                fprintf(stderr, "f-xy-st: %x-%x-%x\n", f, xy, stage_1 + 1);
                fprintf(stderr, "  old k0: %08x\n", k0n);
                fprintf(stderr, "  crc32tab[lsb k0]: %02x\n",
                        crc32tab[k0n & 0xff]);
                fprintf(stderr, "  x: %02x, crc32tab[x]: %08x\n",
                        bytes[stage_1], crc32tab[bytes[stage_1]]);
                k0n = crc32(k0n, bytes[stage_1]);
                fprintf(stderr, "  new k0: %08x\n", k0n);
                uint8_t lsbk0n = k0n & 0xff;
                fprintf(stderr, "  old k1: %08x\n", k1);
                fprintf(stderr, "  old bound: %08x\n", bound);
                bound = (bound + lsbk0n) * CRYPTCONST + 1;
                fprintf(stderr, "  new bound: %08x\n", bound);
                fprintf(stderr, "  old k1cn: %08x\n", k1cn);
                k1cn = k1cn * CRYPTCONST;
                fprintf(stderr, "  new k1cn: %08x\n", k1cn);
                k1 = (k1 + lsbk0n) * CRYPTCONST + 1;
                fprintf(stderr, "  new k1: %08x\n", k1);
                if (k1 != k1cn + bound) {
                    fprintf(stderr, "k1 mismatch!!\n");
                }
                uint8_t carry_bit =
                    ((k1cn & 0xffffff) + (bound & 0xffffff)) > 0x01000000;
                fprintf(stderr, "  carry: %08x\n", carry_bit);
                bits |= carry_bit << (((3 - stage_1) * 4) + f * 2 + xy);
                fprintf(stderr, "  old k2: %08x\n", k2n);
                k2n = crc32(k2n, k1 >> 24);
                fprintf(stderr, "  new k2: %08x\n", k2n);
                if ((bytes[stage_1] ^ sn) != encrypted[stage_1]) {
                    fprintf(stderr,
                            "Something's wrong: f=%d, xy=%d, stage_1=%d, "
                            "bytes[stage_1]=%02x,"
                            "\n\tsn=%02x, encrypted[stage_1]=%02x, "
                            "bytes[stage_1]^sn=%02x\n",
                            f, xy, stage_1, bytes[stage_1], sn,
                            encrypted[stage_1], bytes[stage_1] ^ sn);
                    abort();
                }
                sn = get_s0(k2n & 0xffff);
                fprintf(stderr, "  s: %02x\n", sn);
            }
        }
    }
    result.carries = bits;
    return result;
}

// Computes one step of the first half of the zip encryption
// Supposing we're on stage n+1,
// x is plaintext[n]
// Set the crc_flag to false for n = 0 and true for n > 0
// k1msb is msb(k10 * CRYPTCONST_POW<n+1>)
// carry is the carry bit for this file and x/y pass
// k0 is crc32(k00, 0) when n=0; gets updated to k0n
// extra is 0 when n=0; gets updated
// upper is the current upper bound on low24(k10*CRYPTCONST_POW<n+1>); may get
// updated lower is the current lower bound on low24(k10*CRYPTCONST_POW<n+1>);
// may get updated
uint8_t first_half_step(uint8_t x, bool crc_flag, uint8_t k1msb, uint8_t carry,
                        uint32_t &k0, uint32_t &extra, uint32_t &upper,
                        uint32_t &lower) {
    if (crc_flag) {
        k0 = crc32(k0, x);
    } else {
        k0 ^= crc32tab[x];
    }
    extra = (extra + (k0 & 0xff)) * CRYPTCONST + 1;
    uint32_t bound = 0x01000000 - (extra & 0x00ffffff);

    if (carry) {
        lower = bound > lower ? bound : lower;
    } else {
        upper = bound < upper ? bound : upper;
    }

    return k1msb + (extra >> 24) + carry;
}

// Finds idxs such that crc32tab[idx] is the xor of offset and some prefix of
// stream_byte. We expect one on average.
void second_half_step(uint16_t offset, uint8_t stream_byte,
                      vector<uint8_t> &idxs,
                      vector<vector<uint16_t>> &preimages) {
    for (uint8_t prefix = 0; prefix < 0x40; ++prefix) {
        uint16_t preimage = preimages[stream_byte][prefix];
        uint16_t xored = offset ^ preimage;
        // For these 8 bits there's one crc32tab entry that matches them
        uint8_t inv = (xored >> 1) & 0xff;
        uint8_t idx = crcinvtab[inv];
        // Check that the other 6 bits match
        // We expect one prefix on average to work.
        uint16_t match = (crc32tab[idx] >> 2) & 0x3fff;
        if (match == xored) {
            idxs.push_back(idx);
        }
    }
}

// Creates a 24-bit key from four 8-bit MSB's by xoring the first
// with the other three
uint32_t toMapKey(uint8_t msbxf0, uint8_t msbyf0, uint8_t msbxf1,
                  uint8_t msbyf1) {
    return (msbxf0 ^ msbyf0) | (uint32_t(msbxf0 ^ msbxf1) << 8) |
           (uint32_t(msbxf0 ^ msbyf1) << 16);
}

void fromMapKey(uint8_t msbxf0, uint32_t mapkey, uint8_t &msbyf0,
                uint8_t &msbxf1, uint8_t &msbyf1) {
    msbyf0 = msbxf0 ^ (mapkey & 0xff);
    msbxf1 = msbxf0 ^ ((mapkey >> 8) & 0xff);
    msbyf1 = msbxf0 ^ ((mapkey >> 16) & 0xff);
}

// info: the info about the archive to attack
// table: vector<vector<stage1a>> table(0x01000000)
void mitm_stage1a(archive_info info, vector<vector<stage1a>> &table,
                  correct_guess *c) {
    // STAGE 1
    //
    // Guess s0, chunk2, chunk3 and carry bits.
    uint8_t xf0 = info.file[0].x[0];
    uint8_t xf1 = info.file[1].x[0];
    uint32_t extra(0);

    for (uint16_t s0 = 0; s0 < 0x100; ++s0) {
        fprintf(stderr, "%02x ", s0);
        if ((s0 & 0xf) == 0xf) {
            fprintf(stderr, "\n");
        }
        for (uint16_t chunk2 = 0; chunk2 < 0x100; ++chunk2) {
            for (uint16_t chunk3 = 0; chunk3 < 0x100; ++chunk3) {
                for (uint8_t carries = 0; carries < 0x10; ++carries) {
                    if (nullptr != c && s0 == c->sx[0][0] &&
                        chunk2 == c->chunk2 && chunk3 == c->chunk3 &&
                        carries == (c->carries >> 12)) {
                        fprintf(stderr, "On correct guess.\n");
                    }
                    uint8_t carryxf0 = carries & 1;
                    uint8_t carryyf0 = (carries >> 1) & 1;
                    uint8_t carryxf1 = (carries >> 2) & 1;
                    uint8_t carryyf1 = (carries >> 3) & 1;
                    uint32_t upper = 0x01000000;  // exclusive
                    uint32_t lower = 0x00000000;  // inclusive

                    uint32_t k0crc = chunk2;
                    uint32_t extra = 0;
                    uint8_t msbxf0 =
                        first_half_step(xf0, false, chunk3, carryxf0, k0crc,
                                        extra, upper, lower);
                    uint8_t yf0 = xf0 ^ s0;
                    k0crc = chunk2;
                    extra = 0;
                    uint8_t msbyf0 =
                        first_half_step(yf0, false, chunk3, carryyf0, k0crc,
                                        extra, upper, lower);
                    if (upper < lower) {
                        if (nullptr != c && s0 == c->sx[0][0] &&
                            chunk2 == c->chunk2 && chunk3 == c->chunk3 &&
                            carries == (c->carries >> 12)) {
                            fprintf(stderr,
                                    "Failed to get correct guess: s0 = %02x, "
                                    "chunk2 = %02x, "
                                    "chunk3 = "
                                    "%02x, carries = %x\n",
                                    s0, chunk2, chunk3, carries);
                        }
                        continue;
                    }
                    k0crc = chunk2;
                    extra = 0;
                    uint8_t msbxf1 =
                        first_half_step(xf1, false, chunk3, carryxf1, k0crc,
                                        extra, upper, lower);
                    if (upper < lower) {
                        if (nullptr != c && s0 == c->sx[0][0] &&
                            chunk2 == c->chunk2 && chunk3 == c->chunk3 &&
                            carries == (c->carries >> 12)) {
                            fprintf(stderr,
                                    "Failed to get correct guess: s0 = %02x, "
                                    "chunk2 = %02x, "
                                    "chunk3 = "
                                    "%02x, carries = %x\n",
                                    s0, chunk2, chunk3, carries);
                        }
                        continue;
                    }
                    uint8_t yf1 = xf1 ^ s0;
                    k0crc = chunk2;
                    extra = 0;
                    uint8_t msbyf1 =
                        first_half_step(yf1, false, chunk3, carryyf1, k0crc,
                                        extra, upper, lower);
                    if (upper < lower) {
                        if (nullptr != c && s0 == c->sx[0][0] &&
                            chunk2 == c->chunk2 && chunk3 == c->chunk3 &&
                            carries == (c->carries >> 12)) {
                            fprintf(stderr,
                                    "Failed to get correct guess: s0 = %02x, "
                                    "chunk2 = %02x, "
                                    "chunk3 = "
                                    "%02x, carries = %x\n",
                                    s0, chunk2, chunk3, carries);
                        }
                        continue;
                    }
                    uint32_t mk = toMapKey(msbxf0, msbyf0, msbxf1, msbyf1);
                    if (nullptr != c && s0 == c->sx[0][0] &&
                        chunk2 == c->chunk2 && chunk3 == c->chunk3 &&
                        carries == (c->carries >> 12)) {
                        fprintf(stderr,
                                "MSBs: %02x, %02x, %02x, %02x, Mapkey: %08x, "
                                "carries: %x, "
                                "c.carries: %04x\n",
                                msbxf0, msbyf0, msbxf1, msbyf1, mk, carries,
                                c->carries);
                    }
                    stage1a candidate = {uint8_t(s0), uint8_t(chunk2),
                                         uint8_t(chunk3), carries, msbxf0};
                    table[mk].push_back(candidate);
                }
            }
        }
    }
}

// info: the info about the archive to attack
// table: the output of mitm_stage1a
// candidates: an empty list
void mitm_stage1b(archive_info info, vector<vector<stage1a>> &table,
                  vector<stage1_candidate> &candidates, FILE *f,
                  vector<vector<uint16_t>> &preimages, correct_guess *c) {
    // Second half of MITM for stage 1
    bool found_correct = false;
    for (uint16_t s1xf0 = 0; s1xf0 < 0x100; ++s1xf0) {
        for (uint8_t prefix = 0; prefix < 0x40; ++prefix) {
            uint16_t pxf0(preimages[s1xf0][prefix]);
            if (nullptr != c && s1xf0 == c->sx[0][1]) {
                fprintf(stderr, "s1xf0: %02x, prefix: %04x    ", s1xf0, pxf0);
                if ((prefix & 3) == 3) {
                    fprintf(stderr, "\n");
                }
            }
            vector<uint8_t> firsts(0);
            uint8_t s1yf0 = s1xf0 ^ info.file[0].x[1] ^ info.file[0].h[1];
            second_half_step(pxf0, s1yf0, firsts, preimages);
            if (!firsts.size()) {
                continue;
            }
            for (uint16_t s1xf1 = 0; s1xf1 < 0x100; ++s1xf1) {
                vector<uint8_t> seconds(0);
                second_half_step(pxf0, s1xf1, seconds, preimages);
                if (!seconds.size()) {
                    continue;
                }
                vector<uint8_t> thirds(0);
                uint8_t s1yf1 = s1xf1 ^ info.file[1].x[1] ^ info.file[1].h[1];
                second_half_step(pxf0, s1yf1, thirds, preimages);
                if (!thirds.size()) {
                    continue;
                }
                for (auto f : firsts) {
                    for (auto s : seconds) {
                        for (auto t : thirds) {
                            uint32_t mapkey(f | (s << 8) | (t << 16));
                            for (stage1a candidate : table[mapkey]) {
                                stage1_candidate g;
                                g.chunk2 = candidate.chunk2;
                                g.chunk3 = candidate.chunk3;
                                g.cb1 = candidate.cb1;

                                // Get ~4 possible solutions for lo24(k20) =
                                // chunks 1 and 4
                                //       A  B  C  D   k20
                                // ^  E  F  G  H      crc32tab[D]
                                //    ----------
                                //    I  J  K  L      crck20
                                // ^  M  N  O  P      crc32tab[msbk11xf0]
                                //    ----------
                                //    Q  R  S  T      (pxf0 << 2) matches k21xf0

                                // Starting at the bottom, derive 15..2 of KL
                                // from 15..2 of ST and OP
                                uint16_t crck20 =
                                    ((pxf0 << 2) ^
                                     crc32tab[candidate.msbk11xf0]) &
                                    0xfffc;

                                // Now starting at the top, iterate over 64
                                // possibilities for 15..2 of CD
                                for (uint8_t i = 0; i < 64; ++i) {
                                    uint32_t maybek20 =
                                        (preimages[candidate.s0][i] << 2);
                                    // and 4 possibilities for low two bits of D
                                    for (uint8_t lo = 0; lo < 4; ++lo) {
                                        // CD
                                        maybek20 = (maybek20 & 0xfffc) | lo;
                                        // L' = C ^ H
                                        uint8_t match =
                                            (maybek20 >> 8) ^
                                            crc32tab[maybek20 & 0xff];
                                        // If upper six bits of L == upper six
                                        // of L' then we have a candidate
                                        if ((match & 0xfc) == (crck20 & 0xfc)) {
                                            // KL ^ GH = BC.  (BC << 8) | CD =
                                            // BCD.
                                            g.maybek20.push_back(
                                                ((crck20 ^
                                                  crc32tab[maybek20 & 0xff])
                                                 << 8) |
                                                maybek20);
                                        }
                                    }
                                }
                                candidates.push_back(g);

                                if (nullptr != c && s1xf0 == c->sx[0][1] &&
                                    s1xf1 == c->sx[1][1] &&
                                    candidate.s0 == c->sx[0][0] &&
                                    candidate.chunk2 == c->chunk2 &&
                                    candidate.chunk3 == c->chunk3 &&
                                    candidate.cb1 == (c->carries >> 12)) {
                                    found_correct = true;
                                    fprintf(stderr,
                                            "Correct candidates index = %lx\n",
                                            candidates.size() - 1);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    if (c != nullptr && !found_correct) {
        fprintf(stderr,
                "Failed to use correct guess: s1xf0 = %02x, s1xf1 = %02x\n",
                c->sx[0][1], c->sx[1][1]);
    }
    fprintf(stderr, "Stage 1 candidates.size() == %04lx\n", candidates.size());
}
