#include <stdio.h>
#include <stdlib.h>

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <map>
#include <vector>

using namespace std;

// Meet in the middle attack

// Test data
uint32_t test_keys[3] = {0xe4858bae, 0xa8254576, 0x3743e7bb};
uint8_t test_bytes[2][3][10] = {
    {
        // 1st file
        {0x0d, 0x33, 0xb6, 0x64, 0x5e, 0x66, 0xc0, 0x02, 0xfe, 0x13},  // rand
        {0x17, 0x44, 0xd0, 0xe8, 0x08, 0x48, 0x09, 0x89, 0x1d, 0x5f},  // 1st
        {0x0d, 0xde, 0x72, 0xc2, 0x22, 0x5e, 0xaf, 0x75, 0x8a, 0x6c},  // 2nd
    },
    {
        // 2nd file
        {0x4e, 0x8a, 0x3c, 0x9a, 0x72, 0x23, 0x41, 0xbe, 0xab, 0xb0},  // rand
        {0x54, 0x34, 0xf2, 0x0b, 0x6b, 0x08, 0x3d, 0x17, 0xb2, 0xbf},  // 1st
        {0x4e, 0xc3, 0x69, 0xf4, 0x97, 0x6e, 0x5a, 0x66, 0x77, 0xcb},  // 2nd
    }};

#define CRYPTCONST 0x08088405
#define CRYPTCONST_POW2 0xd4652819
#define CRYPTCONST_POW3 0x576eac7d
#define CRYPTCONST_POW4 0x1201d271
#define CRYPTCONST_INV 0xd94fa8cd

static const uint32_t crc32tab[256] = {
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

uint32_t crc32(uint32_t x, uint8_t y) {
  return (x >> 8) ^ crc32tab[y] ^ crc32tab[x & 0xff];
}

// crcinvtab[(crc32tab[i] >> 3) & 0xff] == i
static const uint8_t crcinvtab[256] = {
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

typedef struct stage1a {
  uint8_t s0;
  uint8_t chunk2;
  uint8_t chunk3;
  uint8_t cb;
  // We don't need the space, but if we did we could recompute msbk11xf0 as
  // chunk3 + (((chunk2 ^ crc32tab[test_bytes[0][0][0]]) * CRYPTCONST + 1) >>
  // 24) + (cb & 1)
  uint8_t msbk11xf0;
} stage1a;

typedef struct guess1 {
  uint8_t s0;
  uint8_t chunk2;
  uint8_t chunk3;
  uint8_t cb;
  uint16_t crck20;
  uint8_t s1xf0;
  uint8_t prefix;
  uint8_t s1xf1;
  uint32_t k11msbs;
  // Could compute these from s1s, prefix, and k11msbs
  uint16_t k21xf0;
  uint16_t k21xf1;
  uint16_t k21yf0;
  uint16_t k21yf1;
} guess1;

vector<vector<uint16_t>> preimages(0x100);

vector<guess1> s1candidates(0);

uint8_t first_half_step(uint8_t x, bool crc_flag, uint8_t k1msb, uint8_t carry,
                        uint32_t &k0, uint32_t &upper, uint32_t &lower) {
  if (crc_flag) {
    k0 = crc32(k0, x);
  } else {
    k0 ^= crc32tab[x];
  }
  uint32_t lsbc = (k0 & 0xff) * CRYPTCONST + 1;
  uint32_t bound = 0x01000000 - (lsbc & 0x00ffffff);

  if (carry) {
    lower = bound > lower ? bound : lower;
  } else {
    upper = bound < upper ? bound : upper;
  }

  return k1msb + (lsbc >> 24) + carry;
}

void second_half_step(uint16_t offset, uint8_t stream_byte,
                      vector<uint8_t> &idxs) {
  for (uint8_t prefix = 0; prefix < 0x40; ++prefix) {
    uint16_t preimage = preimages[stream_byte][prefix];
    uint16_t xored = offset ^ preimage;
    uint8_t inv = (xored >> 1) & 0xff;
    uint8_t idx = crcinvtab[inv];
    uint16_t match = (crc32tab[idx] >> 2) & 0x3fff;
    if (match == xored) {
      idxs.push_back(idx);
    }
  }
}

void stage1() {
  // STAGE 1
  //
  // Guess s0, chunk2, chunk3 and carry bits.
  vector<vector<stage1a>> table1(0x01000000);
  uint8_t xf0 = test_bytes[0][0][0];
  uint8_t xf1 = test_bytes[1][0][0];
  uint32_t total_mapkeys(0);

  for (uint16_t s0 = 0; s0 < 0x100; ++s0) {
    fprintf(stderr, "%02x ", s0);
    if ((s0 & 0xf) == 0xf) {
      fprintf(stderr, "\n");
    }
    for (uint16_t chunk2 = 0; chunk2 < 0x100; ++chunk2) {
      for (uint16_t chunk3 = 0; chunk3 < 0x100; ++chunk3) {
        for (uint8_t carries = 0; carries < 0x10; ++carries) {
          uint8_t carryxf0 = carries & 1;
          uint8_t carryyf0 = (carries >> 1) & 1;
          uint8_t carryxf1 = (carries >> 2) & 1;
          uint8_t carryyf1 = (carries >> 3) & 1;
          uint32_t upper = 0x01000000;  // exclusive
          uint32_t lower = 0x00000000;  // inclusive

          uint32_t k0crc = chunk2;
          uint8_t msbxf0 = first_half_step(xf0, false, chunk3, carryxf0, k0crc,
                                           upper, lower);
          uint8_t yf0 = xf0 ^ s0;
          k0crc = chunk2;
          uint8_t msbyf0 = first_half_step(yf0, false, chunk3, carryyf0, k0crc,
                                           upper, lower);
          if (upper < lower) {
            continue;
          }
          k0crc = chunk2;
          uint8_t msbxf1 = first_half_step(xf1, false, chunk3, carryxf1, k0crc,
                                           upper, lower);
          if (upper < lower) {
            continue;
          }
          uint8_t yf1 = xf1 ^ s0;
          k0crc = chunk2;
          uint8_t msbyf1 = first_half_step(yf1, false, chunk3, carryyf1, k0crc,
                                           upper, lower);
          if (upper < lower) {
            continue;
          }
          uint32_t mk = toMapKey(msbxf0, msbyf0, msbxf1, msbyf1);
          stage1a c = {uint8_t(s0), uint8_t(chunk2), uint8_t(chunk3), carries,
                       msbxf0};
          if (!table1[mk].size()) {
            ++total_mapkeys;
          }
          table1[mk].push_back(c);
        }
      }
    }
  }

  // Second half of MITM for stage 1
  for (uint16_t s1xf0 = 0; s1xf0 < 0x100; ++s1xf0) {
    for (uint8_t prefix = 0; prefix < 0x40; ++prefix) {
      uint16_t pxf0(preimages[s1xf0][prefix]);
      vector<uint8_t> firsts(0);
      uint8_t s1yf0 = s1xf0 ^ test_bytes[0][0][1] ^ test_bytes[0][2][1];
      second_half_step(pxf0, s1yf0, firsts);
      if (!firsts.size()) {
        continue;
      }
      bool done = false;
      for (uint16_t s1xf1 = 0; s1xf1 < 0x100 && !done; ++s1xf1) {
        vector<uint8_t> seconds(0);
        second_half_step(pxf0, s1xf1, seconds);
        if (!seconds.size()) {
          done = true;
          continue;
        }
        vector<uint8_t> thirds(0);
        uint8_t s1yf1 = s1xf1 ^ test_bytes[1][0][1] ^ test_bytes[1][2][1];
        second_half_step(pxf0, s1yf1, thirds);
        if (!thirds.size()) {
          done = true;
          continue;
        }
        for (auto f : firsts) {
          for (auto s : seconds) {
            for (auto t : thirds) {
              uint32_t mapkey(f | (s << 8) | (t << 16));
              for (auto c : table1[mapkey]) {
                guess1 g;
                g.s0 = c.s0;
                g.chunk2 = c.chunk2;
                g.chunk3 = c.chunk3;
                g.cb = c.cb;
                g.crck20 = ((pxf0 << 2) ^ crc32tab[c.msbk11xf0]) & 0xffff;
                // Can iterate thru 64 preimages of s0 * 2 low bits to find
                // a:b:low s.t. 7..2 of (a ^ crc32tab[b:low]) = 7..2 of crck20;
                // get 4 solutions for msb crck20
                // Don't need to do it here.
                g.k11msbs = mapkey ^ (c.msbk11xf0 * 0x01010101);
                g.k21xf0 = pxf0;
                g.k21yf0 = preimages[s1yf0][f];
                g.k21xf1 = preimages[s1xf1][s];
                g.k21yf1 = preimages[s1yf1][t];
                s1candidates.push_back(g);
              }
            }
          }
        }
      }
    }
  }

  fprintf(stderr, "total_mapkeys = %04x, s1candidates.size() == %04lx\n",
          total_mapkeys, s1candidates.size());
}

typedef struct stage2a {
  guess1 g;
  uint8_t chunk6;
  uint8_t chunk7;
  uint8_t cb;
  uint8_t msbk12xf0;
} stage2a;

typedef struct guess2 {
  guess1 g1;
  uint8_t chunk6;
  uint8_t chunk7;
  uint8_t cb2;
  uint32_t k12msbs;
  uint8_t s2xf0;
  uint8_t s2xf1;
} guess2;

vector<guess2> s2candidates(0);
void stage2() {
  uint32_t total_mapkeys(0);
  // STAGE 2
  //
  // Guess chunk6, chunk7 and carry bits
  // Keep track of bounds to exclude some carry bit options

  // Now that we have actual k20 bits, check prediction of s2xf0, etc. and
  // filter more
  for (guess1 c1 : s1candidates) {
    uint8_t cb1 = c1.cb;
    uint8_t carryx0f0 = cb1 & 1;
    uint8_t carryy0f0 = (cb1 >> 1) & 1;
    uint8_t carryx0f1 = (cb1 >> 2) & 1;
    uint8_t carryy0f1 = (cb1 >> 3) & 1;

    vector<vector<stage2a>> table2(0x01000000);
    // Monte Carlo sampling of keyspace
    for (uint8_t i = 0; i < 10; ++i) {
      uint16_t chunk6 = rand() & 0xff;
      uint16_t chunk7 = rand() & 0xff;
      //    for (uint16_t chunk6 = 0; chunk6 < 0x100; ++chunk6) {
      //      for (uint16_t chunk7 = 0; chunk7 < 0x100; ++chunk7) {
      for (uint8_t cb2 = 0; cb2 < 0x10; ++cb2) {
        uint8_t carryx1f0 = cb2 & 1;
        uint8_t carryy1f0 = (cb2 >> 1) & 1;
        uint8_t carryx1f1 = (cb2 >> 2) & 1;
        uint8_t carryy1f1 = (cb2 >> 3) & 1;
        uint32_t upper = 0x01000000;
        uint32_t lower = 0x00000000;
        uint32_t k0crc = c1.chunk2 | (chunk6 << 8);
        first_half_step(test_bytes[0][0][0], false, c1.chunk3, carryx0f0, k0crc,
                        upper, lower);
        uint32_t msbxf0 = first_half_step(test_bytes[0][0][1], true, chunk7,
                                          carryx1f0, k0crc, upper, lower);
        k0crc = c1.chunk2 | (chunk6 << 8);
        first_half_step(test_bytes[0][0][0] ^ c1.s0, false, c1.chunk3,
                        carryy0f0, k0crc, upper, lower);
        uint32_t msbyf0 =
            first_half_step(test_bytes[0][0][1] ^ c1.s1xf0, true, chunk7,
                            carryy1f0, k0crc, upper, lower);
        if (upper < lower) {
          continue;
        }
        k0crc = c1.chunk2 | (chunk6 << 8);
        first_half_step(test_bytes[1][0][0], false, c1.chunk3, carryx0f1, k0crc,
                        upper, lower);
        uint32_t msbxf1 = first_half_step(test_bytes[1][0][1], true, chunk7,
                                          carryx1f1, k0crc, upper, lower);
        if (upper < lower) {
          continue;
        }
        k0crc = c1.chunk2 | (chunk6 << 8);
        first_half_step(test_bytes[1][0][0] ^ c1.s0, false, c1.chunk3,
                        carryy0f1, k0crc, upper, lower);
        uint32_t msbyf1 =
            first_half_step(test_bytes[1][0][1] ^ c1.s1xf1, true, chunk7,
                            carryy1f1, k0crc, upper, lower);
        if (upper < lower) {
          continue;
        }
        uint32_t mk = toMapKey(msbxf0, msbyf0, msbxf1, msbyf1);
        stage2a s2a;
        s2a.g = c1;
        s2a.chunk6 = chunk6;
        s2a.chunk7 = chunk7;
        s2a.cb = cb2;
        s2a.msbk12xf0 = msbxf0;
        if (!table2[mk].size()) {
          ++total_mapkeys;
        }
        table2[mk].push_back(s2a);
      }
    }
    //      }
    //    }

    // Second half of MITM for stage 2
    /*
    crc32(k21x, msbk12x) ^ crc32(k21y, msbk12y)
    = crc32(crc32(k20, msbk11x), msbk12x) ^ crc32(crc32(k20, msbk11x), msbk12y)
    = crc32(crc32(k20, msbk11x) ^ crc32(k20, msbk11x), msbk12x ^ msbk12y)
    = crc32(crc32(0, msbk11x ^ msbk11y), msbk12x ^ msbk12y)
    = crc32(crc32tab[msbk11x ^ msbk11y], msbk12x ^ msbk12y)
    = (crc32tab[msbk11x ^ msbk11y] >> 8) ^ crc32tab[(crc32tab[msbk11x ^ msbk11y]
    & 0xff) ^ msbk12x ^ msbk12y]
    */
    // Should I store mk instead of k11msbs?
    uint32_t mk1 = c1.k11msbs ^ ((c1.k11msbs >> 24) * 0x01010101);
    uint32_t cyf0 = crc32tab[mk1 & 0xff];
    uint32_t cxf1 = crc32tab[(mk1 >> 8) & 0xff];
    uint32_t cyf1 = crc32tab[(mk1 >> 16) & 0xff];
    for (uint16_t s2xf0 = 0; s2xf0 < 0x100; ++s2xf0) {
      for (uint16_t s2xf1 = 0; s2xf1 < 0x100; ++s2xf1) {
        for (uint8_t prefix = 0; prefix < 0x40; ++prefix) {
          uint16_t pxf0(preimages[s2xf0][prefix]);

          vector<uint8_t> firsts(0);
          uint8_t s2yf0 = s2xf0 ^ test_bytes[0][0][2] ^ test_bytes[0][2][2];
          // >> 10 is >> 8 from the last line in the equation above plus >> 2
          // for moving bits 15..2 to 13..0
          second_half_step(pxf0 ^ (cyf0 >> 10), s2yf0, firsts);
          if (!firsts.size()) {
            continue;
          }
          vector<uint8_t> seconds(0);
          second_half_step(pxf0 ^ (cxf1 >> 10), s2xf1, seconds);
          if (!seconds.size()) {
            continue;
          }
          vector<uint8_t> thirds(0);
          uint8_t s2yf1 = s2xf0 ^ test_bytes[1][0][2] ^ test_bytes[1][2][2];
          second_half_step(pxf0 ^ (cyf1 >> 10), s2yf1, thirds);
          if (!thirds.size()) {
            continue;
          }
          for (auto f : firsts) {
            for (auto s : seconds) {
              for (auto t : thirds) {
                // xoring with these c?f? bytes as in the last line of the
                // equation above
                uint32_t mapkey((f ^ (cyf0 & 0xff)) |
                                ((s ^ (cxf1 & 0xff)) << 8) |
                                ((t ^ (cyf1 & 0xff)) << 16));
                for (auto c2 : table2[mapkey]) {
                  if (pxf0 != (crc32(c1.k21xf0, c2.msbk12xf0) & 0x3f)) {
                    continue;
                  }
                  guess2 g;
                  g.g1 = c2.g;
                  g.chunk6 = c2.chunk6;
                  g.chunk7 = c2.chunk7;
                  g.cb2 = c2.cb;
                  g.k12msbs = mapkey ^ (c2.msbk12xf0 * 0x01010101);
                  g.s2xf0 = s2xf0;
                  g.s2xf1 = s2xf1;
                  s2candidates.push_back(g);
                }
              }
            }
          }
        }
      }
    }
  }

  fprintf(stderr, "total_mapkeys = %04x, s2candidates.size() == %04lx\n",
          total_mapkeys, s2candidates.size());
}

int main() {
  // Build preimage lookup table
  for (uint16_t k20 = 0; k20 < 0x4000; ++k20) {
    uint16_t temp = (k20 << 2) | 3;
    uint8_t s = ((temp * (temp ^ 1)) >> 8) & 0xff;
    preimages[s].push_back(k20);
  }

  stage1();

  return 0;
}