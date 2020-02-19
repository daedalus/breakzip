/**
 * Copyright (c) 2020, Pyrofex Corporation. All Rights Reserved.
 * Author: Nash E. Foster <leaf@pyrofex.net>, Michael A. Stay <stay@pyrofex.net>
 */
#include <stdlib.h>

#include "breakzip.h"

namespace mitm {

archive_info test[3] = {
    // test 0
    {  // file
     { // file 0
      {// x
       {0x0d, 0x33, 0xb6, 0x64, 0x5e, 0x66, 0xc0, 0x02, 0xfe, 0x13},
       // h
       {0x0d, 0xde, 0x72, 0xc2, 0x22, 0x5e, 0xaf, 0x75, 0x8a, 0x6c},
       // y
       {0x17, 0x44, 0xd0, 0xe8, 0x08, 0x48, 0x09, 0x89, 0x1d, 0x5f}},
      // file 1
      {// x
       {0x4e, 0x8a, 0x3c, 0x9a, 0x72, 0x23, 0x41, 0xbe, 0xab, 0xb0},
       // h
       {0x4e, 0xc3, 0x69, 0xf4, 0x97, 0x6e, 0x5a, 0x66, 0x77, 0xcb},
       // y
       {0x54, 0x34, 0xf2, 0x0b, 0x6b, 0x08, 0x3d, 0x17, 0xb2, 0xbf}}},
     // key
     {0xe4858bae, 0xa8254576, 0x3743e7bb}},
    // test 1
    {  // file
     { // file 0
      {// x
       {0x20, 0x95, 0x07, 0xa5, 0xb9, 0x4c, 0x99, 0xcc, 0xe7, 0x4a},
       // h
       {0x20, 0x7e, 0xbd, 0xf1, 0xb2, 0x4e, 0xd9, 0xea, 0xa9, 0xc6},
       // y
       {0x12, 0x27, 0x02, 0xf6, 0x62, 0xe7, 0x23, 0xfc, 0x18, 0xb5}},
      // file 1
      {// x
       {0x3d, 0xff, 0x6c, 0xe0, 0x91, 0xbf, 0xc2, 0x2b, 0xca, 0x90},
       // h
       {0x3d, 0x4c, 0xed, 0x9f, 0x49, 0xf9, 0x78, 0x53, 0xee, 0x14},
       // y
       {0x0f, 0xe4, 0xa7, 0x4a, 0x4d, 0x82, 0x82, 0x1e, 0xc9, 0x57}}},
     // key
     {0x1e096225, 0xcb831619, 0x296e7f2b}},
    // test 2
    {  // file
     { // file 0
      {// x
       {0x56, 0x28, 0xf7, 0x7d, 0xf8, 0x4e, 0x9a, 0x32, 0x38, 0x8b},
       // h
       {0x56, 0x01, 0x88, 0x79, 0x3f, 0x36, 0x44, 0xbb, 0xdf, 0x02},
       // y
       {0x25, 0x37, 0x5c, 0xe3, 0xf0, 0x2e, 0x3c, 0x25, 0x11, 0x55}},
      // file 1
      {// x
       {0x9a, 0x88, 0x62, 0x14, 0xa5, 0x6b, 0xf8, 0x2c, 0x58, 0x05},
       // h
       {0x9a, 0x6a, 0xed, 0xae, 0x4d, 0x27, 0x0a, 0x16, 0xe8, 0x45},
       // y
       {0xe9, 0xc5, 0xb5, 0x58, 0x15, 0xf3, 0x00, 0xad, 0xf8, 0x13}}},
     // key
     {0x7d9315a2, 0xfa9f7fba, 0x15be19ef}}};

void build_preimages(vector<vector<uint16_t>> &preimages) {
    // Build preimage lookup table
    for (uint16_t k20 = 0; k20 < 0x4000; ++k20) {
        uint16_t temp = (k20 << 2) | 3;
        uint8_t s = ((temp * (temp ^ 1)) >> 8) & 0xff;
        preimages[s].push_back(k20);
    }
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

    fprintf(stderr,
            "Result\nchunks: 1=%04x 2=%02x 3=%02x 4=%02x 5=%02x 6=%02x 7=%02x "
            "8=%02x 9=%02x 10= %02x 11=%02x\n",
            result.chunk1, result.chunk2, result.chunk3, result.chunk4,
            result.chunk5, result.chunk6, result.chunk7, result.chunk8,
            result.chunk9, result.chunk10, result.chunk11);
    for (int f = 0; f < 2; ++f) {
        for (int s = 0; s < 10; ++s) {
            result.sx[f][s] = info.file[f].x[s] ^ info.file[f].y[s];
            fprintf(stderr, "%02x, ", result.sx[f][s]);
        }
        fprintf(stderr, "\n");
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
    fprintf(stderr, "carries: %04x\n", bits);

    return result;
}

void read_word(FILE *f, uint32_t &w) {
    auto c1 = fgetc(f);
    auto c2 = fgetc(f);
    auto c3 = fgetc(f);
    auto c4 = fgetc(f);
    w = (c4 << 24) | (c3 << 16) | (c2 << 8) | c1;
}

void write_word(FILE *f, uint32_t w) {
    fputc(w & 0xff, f);
    fputc((w >> 8) & 0xff, f);
    fputc((w >> 16) & 0xff, f);
    fputc((w >> 24) & 0xff, f);
}

void write_3bytes(FILE *f, uint32_t w) {
    fputc(w & 0xff, f);
    fputc((w >> 8) & 0xff, f);
    fputc((w >> 16) & 0xff, f);
}

void read_3bytes(FILE *f, uint32_t &w) {
    auto c1 = fgetc(f);
    auto c2 = fgetc(f);
    auto c3 = fgetc(f);
    w = (c3 << 16) | (c2 << 8) | c1;
}

uint8_t get_s0(uint16_t k20) {
    uint16_t temp = k20 | 3;
    return (temp * (temp ^ 1)) >> 8;
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
void second_half_step(const uint16_t offset, const uint8_t stream_byte,
                      vector<uint8_t> &idxs) {
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

};  // namespace mitm
