// Find the possible neighboring lattice points that the four msb(k10*c**n) bytes could give
// gcc -std=c++17 -lstdc++ neighbors.cpp; chmod 755 a.out; ./a.out

#include <stdio.h>
#include <cstdint>
#include <map>
#include <vector>
#include <cmath>

int64_t m1 = 0xffffffffL;
int64_t m2 = 0xff000000L;
int64_t c = 0x008088405L;
int64_t c2 = (c * c) & m1;
int64_t c3 = (c2 * c) & m1;
int64_t c4 = (c3 * c) & m1;

typedef std::vector<int64_t> vec;

int main() {
  int32_t k10;
  std::map<vec, uint32_t> seen;
  
  for (k10 = 0; k10 < 0x1000000; ++k10) {
    if (0 == (k10 & 0xffff)) { printf("%08x, %ld\n", k10, seen.size()); }

    vec truth = {
      (k10 * c) & m1,
      (k10 * c2) & m1,
      (k10 * c3) & m1,
      (k10 * c4) & m1
    };

    vec msbs = {
      truth[0] & m2,
      truth[1] & m2,
      truth[2] & m2,
      truth[3] & m2
    };

    vec secret = { truth[0] - msbs[0], truth[1] - msbs[1], truth[2] - msbs[2], truth[3] - msbs[3] };

    vec w = {
      +109 * msbs[0]  -18 * msbs[1] -125 * msbs[2]  +74 * msbs[3],
       +72 * msbs[0] -145 * msbs[1]  -60 * msbs[2] -163 * msbs[3],
      -108 * msbs[0] -123 * msbs[1]  -19 * msbs[2] +198 * msbs[3],
      -319 * msbs[0] +137 * msbs[1] -245 * msbs[2]  -85 * msbs[3]
    };

    for (int i = 0; i < 4; ++i) {
      w[i] = -(w[i] & m1);
    }

    vec guess = {
      ( 13604679 * w[0]   -563513 * w[1]  -8196160 * w[2] -6167539 * w[3]) >> 32,
      (  4624483 * w[0] -16015901 * w[1] -13783360 * w[2] +2631745 * w[3]) >> 32,
      (-18096657 * w[0]  -4513425 * w[1]    -38464 * w[2] -7189179 * w[3]) >> 32,
      (  8556971 * w[0] -10689749 * w[1]  +8655040 * w[2] -2419111 * w[3]) >> 32
    };

    vec diff = {
      secret[0] - guess[0],
      secret[1] - guess[1],
      secret[2] - guess[2],
      secret[3] - guess[3]
    };

    uint32_t count = seen[diff];
    seen[diff] = count + 1;
  }
  for (const auto& elem: seen) {
      printf("{ %lx, %lx, %lx, %lx, %08x },\n", 
              elem.first[0], elem.first[1], 
              elem.first[2], elem.first[3], elem.second);
  }
}
