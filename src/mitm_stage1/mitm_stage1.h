#ifndef MITM_STAGE1_H
#define MITM_STAGE1_H

#include <stdio.h>
#include <cstdint>
#include <vector>

using namespace std;

#define CRYPTCONST 0x08088405
#define CRYPTCONST_POW2 0xd4652819
#define CRYPTCONST_POW3 0x576eac7d
#define CRYPTCONST_POW4 0x1201d271
#define CRYPTCONST_INV 0xd94fa8cd

typedef struct file_info {
  uint8_t x[10];
  uint8_t h[10];
  // Only for tests
  uint8_t y[10];
} file_info;

typedef struct archive_info {
  file_info file[2];
  // Only for tests
  uint32_t key[3];
  } archive_info;

typedef struct correct_guess {
  uint16_t chunk1; // Bits 15..0  of key20
  uint8_t chunk2;  // Bits 7..0   of crc32(key00, 0)
  uint8_t chunk3;  // Bits 31..24 of key10 * 0x08088405
  uint8_t chunk4;  // Bits 23..16 of key20
  uint8_t chunk5;  // Bits 31..24 of key20
  uint8_t chunk6;  // Bits 15..8  of crc32(key00, 0)
  uint8_t chunk7;  // Bits 31..24 of key10 * (0x08088405 ** 2)
  uint8_t chunk8;  // Bits 23..16 of crc32(key00, 0)
  uint8_t chunk9;  // Bits 31..24 of key10 * (0x08088405 ** 3)
  uint8_t chunk10; // Bits 31..24 of crc32(key00, 0)
  uint8_t chunk11; // Bits 31..24 of key10 * (0x08088405 ** 4)
  // carry bits:
  // stage: 1111222233334444
  // file:  1100110011001100
  // xy:    1010101010101010
  uint16_t carries;
  uint8_t sx[2][4];
} correct_guess;

typedef struct stage1_candidate {
  // Expect four candidates for chunks 1, 4
  vector<uint32_t> maybek20;
  uint8_t chunk2;
  uint8_t chunk3;
  uint8_t cb1;
} stage1_candidate;

typedef struct stage1a {
  uint8_t s0;
  uint8_t chunk2;
  uint8_t chunk3;
  uint8_t cb1;
  uint8_t msbk11xf0;
} stage1a;

void build_preimages(vector<vector<uint16_t>>& preimages);

correct_guess correct(archive_info info);

void mitm_stage1a(archive_info info, vector<vector<stage1a>>& table, correct_guess *c = nullptr);
void mitm_stage1b(archive_info info, vector<vector<stage1a>>& table, vector<stage1_candidate>& candidates, FILE *f, vector<vector<uint16_t>>& preimages, correct_guess *c = nullptr);

#endif
