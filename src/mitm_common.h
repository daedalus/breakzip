#ifndef MITM_COMMON_H
#define MITM_COMMON_H

#include <stdio.h>
#include <cstdint>
#include <vector>

using namespace std;

#define CRYPTCONST 0x08088405
#define CRYPTCONST_POW2 0xd4652819
#define CRYPTCONST_POW3 0x576eac7d
#define CRYPTCONST_POW4 0x1201d271
#define CRYPTCONST_INV 0xd94fa8cd

namespace mitm {

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

extern archive_info test[2];

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

void read_word(FILE *f, uint32_t &w);
void write_word(FILE *f, uint32_t w);
void write_3bytes(FILE *f, uint32_t w);
void read_3bytes(FILE *f, uint32_t &w);

void build_preimages(vector<vector<uint16_t>>& preimages);
correct_guess correct(archive_info info);
uint8_t get_s0(uint16_t k20);
uint8_t first_half_step(uint8_t x, bool crc_flag, uint8_t k1msb, uint8_t carry,
                        uint32_t &k0, uint32_t &extra, uint32_t &upper,
                        uint32_t &lower);
void second_half_step(const uint16_t offset,
                      const uint8_t stream_byte,
                      vector<uint8_t> &idxs,
                      const vector<vector<uint16_t>>& preimages);
uint32_t toMapKey(uint8_t msbxf0, uint8_t msbyf0, uint8_t msbxf1,
                  uint8_t msbyf1);
void fromMapKey(uint8_t msbxf0, uint32_t mapkey, uint8_t &msbyf0,
                uint8_t &msbxf1, uint8_t &msbyf1);

}; // namespace
#endif
