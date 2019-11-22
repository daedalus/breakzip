/***
 * Author: Nash E. Foster <leaf@pyrofex.net>
 */

#include "stages.h"
#include "breakzip.h"

#include <algorithm>

//#define CGPRINT(x, ...) if ((correct_guess != 0) && (guess_bits == correct_guess)) { \
//    fprintf(stderr, x, __VA_ARGS__); \
//}
//#define CGABORT(x, ...) if ((correct_guess != 0) && (guess_bits == correct_guess)) { \
//    fprintf(stderr, x, __VA_ARGS__); \
//    abort(); \
//}

#define DEBUG false
#define DPRINT(x, ...) if (DEBUG) { fprintf(stderr, x, __VA_ARGS__); }


#define LSB32(x) ((uint8_t)(0x000000ff & x))
#define MSB32(x) ((uint8_t)((0xff000000 & x) >> 24))

namespace breakzip {
    using namespace std;

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
        0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d

    };

    uint32_t crc32 (uint32_t x, uint8_t y) {
        return (x>>8) ^ crc32tab[y] ^ crc32tab[x & 0xff];
    }


    /* Functions for calculating the chunks from key material. */
    uint16_t chunk1_from_keys(const std::array<uint32_t, 3> &k) {
        const uint16_t chunk1 = k[2] & 0xffff;
        return chunk1;
    }

    uint8_t chunk2_from_keys(const std::array<uint32_t, 3> &k) {
        uint8_t chunk2 = crc32(k[0], 0) & 0xff;
        return chunk2;
    }

    uint8_t chunk3_from_keys(const std::array<uint32_t, 3> &k) {
        const uint8_t chunk3  = (k[1] * CRYPTCONST) >> 24;
        return chunk3;
    }

    uint8_t chunk4_from_keys(const std::array<uint32_t, 3> &k) {
        const uint8_t chunk4 = (k[2] >> 16) & 0xff;
        return chunk4;
    }

    uint8_t chunk5_from_keys(const std::array<uint32_t, 3> &k) {
        const uint8_t chunk5 = (k[2] >> 24) & 0xff;
        return chunk5;
    }

    uint8_t chunk6_from_keys(const std::array<uint32_t, 3> &k) {
        const uint8_t chunk6 = (crc32(k[0], 0) >> 8) & 0xff;
        return chunk6;
    }

    uint8_t chunk7_from_keys(const std::array<uint32_t, 3> &k) {
        const uint8_t chunk7 = (k[1] * CRYPTCONST_POW2) >> 24;
        return chunk7;
    }

    uint16_t get_s0(const uint16_t chunk1) {
        const uint16_t tmp = chunk1 | 3;
        const uint16_t s0 = ((tmp * (tmp ^ 1)) >> 8) & 0xff;
        return s0;
    }

    uint16_t get_s0(const guess_t& guess) {
        return get_s0(guess.chunk1);
    }

    guess_t correct_guess_start(uint8_t stage, guess_t correct) {
        guess_t mine = correct;
        switch (stage) {
            case 1:
                mine.carry_bits.set(1, 0);
                mine.chunk1 = 0;
                break;
            case 2:
                mine.carry_bits.set(2, 0);
                mine.chunk5 = 0;
                break;
            case 3:
                mine.carry_bits.set(3, 0);
                mine.chunk8 = 0;
                break;
            case 4:
                mine.carry_bits.set(4, 0);
                mine.chunk10 = 0;
                break;
            default:
                break;
        }
        if (DEBUG) {
            fprintf(stderr, "correct_guess_start: correct: %s\n"
                    "correct_guess_start:   mine: %s\n",
                    correct.str().c_str(), mine.str().c_str());
        }
        return mine;
    }

    guess_t correct_guess_end(uint8_t stage, guess_t correct) {
        guess_t mine = correct;
        switch (stage) {
            case 1:
                mine.carry_bits.set(1, 0xf);
                mine.chunk1 = 0xffff;
                break;
            case 2:
                mine.carry_bits.set(2, 0xf);
                mine.chunk5 = 0xff;
                break;
            case 3:
                mine.carry_bits.set(3, 0xf);
                mine.chunk8 = 0xff;
                break;
            case 4:
                mine.carry_bits.set(4, 0xf);
                mine.chunk10 = 0xff;
                break;
            default:
                break;
        }
        if (DEBUG) {
            fprintf(stderr, "correct_guess_end: correct: %s\n"
                    "correct_guess_end:   mine: %s\n",
                    correct.str().c_str(), mine.str().c_str());
        }
        return mine;
    }

    guess_t stage1_correct_guess_start(guess_t correct_guess) {
        return correct_guess_start(1, correct_guess);
    }

    guess_t stage1_correct_guess_end(guess_t correct_guess) {
        return correct_guess_end(1, correct_guess);
    }

    guess_t stage2_correct_guess_start(guess_t correct_guess) {
        return correct_guess_start(2, correct_guess);
    }

    guess_t stage2_correct_guess_end(guess_t correct_guess) {
        return correct_guess_end(2, correct_guess);
    }

    guess_t correct_guess(uint8_t stage, const crack_t crypt_test) {
        guess_t result(stage);

        const uint32_t k00 = crypt_test.zip.keys[0];
        const uint32_t k10 = crypt_test.zip.keys[1];
        const uint32_t k20 = crypt_test.zip.keys[2];
        const uint32_t crc32k00 = crc32(k00, 0);

        result.chunk2 = (crc32k00 >> 0) & 0xff;
        result.chunk6 = (crc32k00 >> 8) & 0xff;
        result.chunk8 = (crc32k00 >> 16) & 0xff;
        result.chunk10 = (crc32k00 >> 24) & 0xff;

        result.chunk1 = (k20 >> 0) & 0xffff;
        result.chunk4 = (k20 >> 16) & 0xff;
        result.chunk5 = (k20 >> 24) & 0xff;

        result.chunk3 = (k10 * CRYPTCONST) >> 24;
        result.chunk7 = (k10 * CRYPTCONST_POW2) >> 24;
        result.chunk9 = (k10 * CRYPTCONST_POW3) >> 24;
        result.chunk11 = (k10 * CRYPTCONST_POW4) >> 24;

        // xs = crypt_test.zip.files[f].random_bytes[stage]
        // ys = crypt_test.zip.files[f].header_first[stage]
        // carry bits:
        // stage: 1111222233334444
        // file:  1100110011001100
        // xy:    1010101010101010
        uint16_t bits = 0;
        for (int f = 0; f < 2; ++f) {
            for (int xy = 0; xy < 2; ++xy) {
                const uint8_t *bytes = xy ?
                    crypt_test.zip.files[f].header_first :
                    crypt_test.zip.files[f].random_bytes;
                const uint8_t *encrypted = xy ?
                    crypt_test.zip.files[f].header_second :
                    crypt_test.zip.files[f].header_first;
                uint32_t bound = 0;
                uint32_t k0n = k00;
                uint32_t k1cn = k10;
                uint32_t k2n = k20;
                uint8_t sn = get_s0(k20 & 0xffff);
                // stage_1 should be thought of as "stage - 1"
                for (int stage_1 = 0; stage_1 < 4; ++stage_1) {
                    k0n = crc32(k0n, bytes[stage_1]);
                    uint8_t lsbk0n = k0n & 0xff;
                    bound = (bound + lsbk0n) * CRYPTCONST + 1;
                    k1cn = k1cn * CRYPTCONST;
                    uint8_t carry_bit = ((k1cn & 0xffffff) + (bound & 0xffffff)) > 0x01000000;
                    bits |= carry_bit << (((3 - stage_1) * 4) + f * 2 + xy);
                    k2n = crc32(k2n, (k1cn + bound)>>24);
                    if ((bytes[stage_1] ^ sn) != encrypted[stage_1]) {
                        fprintf(stderr, "Something's wrong: f=%d, xy=%d, stage_1=%d, bytes[stage_1]=%02x,"
                                        "\n\tsn=%02x, encrypted[stage_1]=%02x, bytes[stage_1]^sn=%02x\n",
                                        f, xy, stage_1, bytes[stage_1],
                                        sn, encrypted[stage_1], bytes[stage_1] ^ sn);
                        abort();
                    }
                    sn = get_s0(k2n & 0xffff);
                }
            }
        }
        result.carry_bits.bits = bits;
        return result;
    }

    uint8_t step(const bool do_crc, const uint8_t k1chunk, const uint8_t byte,
            const uint8_t carry_bit, const uint8_t fileidx,
            uint32_t& k0 /* out */, uint32_t& bound /* out */,
            uint32_t& k2 /* out */) {

        k0 = do_crc ? crc32(k0, byte) : k0 ^ crc32tab[byte];
        const uint8_t lsbkey0n = k0 & 0xff;
        bound = bound * CRYPTCONST + lsbkey0n * CRYPTCONST + 1;
        const uint8_t msb_key1n =
            k1chunk + (bound >> 24) + carry_bit;
        k2 = crc32(k2, msb_key1n);
        const uint32_t s1n_temp = (k2 | 3) & 0xffff;
        const uint8_t s1n = ((s1n_temp * (s1n_temp ^ 1)) >> 8) & 0xff;
        return s1n;
    }

    int next(int stage, const crack_t* state, const vector<guess_t>& in,
            vector<guess_t>& out) {

        for (auto candidate: in) {
            uint16_t chunk1 = 0;
            uint8_t chunk2 = 0;
            uint8_t chunk3 = 0;
            uint8_t chunk4 = 0;
            uint8_t chunk5 = 0;
            uint8_t chunk6 = 0;
            uint8_t chunk7 = 0;
            uint8_t chunk8 = 0;
            uint8_t chunk9 = 0;
            uint8_t chunk10 = 0;
            uint8_t chunk11 = 0;
            carrybits_t bits(candidate.carry_bits);

            switch (stage) {
                // Fall-throughs are on purpose
                case 7:
                case 6:
                case 5:
                    chunk11 = candidate.chunk11;
                    chunk10 = candidate.chunk10;
                case 4:
                    chunk9 = candidate.chunk9;
                    chunk8 = candidate.chunk8;
                case 3:
                    chunk7 = candidate.chunk7;
                    chunk6 = candidate.chunk6;
                    chunk5 = candidate.chunk5;
                case 2:
                    chunk4 = candidate.chunk4;
                    chunk3 = candidate.chunk3;
                    chunk2 = candidate.chunk2;
                    chunk1 = candidate.chunk1;
                case 1:
                default:
                    break;
            }

            // TODO(leaf): We have to combine the candidate and the start/end
            // for the following iteration to make sense. It doesn't at the
            // moment.
            for (auto guess: stage_range(stage, *state)) {
                switch (stage) {
                    case 7:
                        break;
                    case 6:
                        break;
                    case 5:
                        break;
                    case 4:
                        chunk11 = guess.chunk11;
                        chunk10 = guess.chunk10;
                        bits.set(4, 0, 0, guess.carry_bits.get(4, 0, 0));
                        bits.set(4, 0, 1, guess.carry_bits.get(4, 0, 1));
                        bits.set(4, 1, 0, guess.carry_bits.get(4, 1, 0));
                        bits.set(4, 1, 1, guess.carry_bits.get(4, 1, 1));
                        break;
                    case 3:
                        chunk9 = guess.chunk9;
                        chunk8 = guess.chunk8;
                        bits.set(3, 0, 0, guess.carry_bits.get(3, 0, 0));
                        bits.set(3, 0, 1, guess.carry_bits.get(3, 0, 1));
                        bits.set(3, 1, 0, guess.carry_bits.get(3, 1, 0));
                        bits.set(3, 1, 1, guess.carry_bits.get(3, 1, 1));
                        break;
                    case 2:
                        chunk7 = guess.chunk7;
                        chunk6 = guess.chunk6;
                        chunk5 = guess.chunk5;
                        bits.set(2, 0, 0, guess.carry_bits.get(2, 0, 0));
                        bits.set(2, 0, 1, guess.carry_bits.get(2, 0, 1));
                        bits.set(2, 1, 0, guess.carry_bits.get(2, 1, 0));
                        bits.set(2, 1, 1, guess.carry_bits.get(2, 1, 1));
                        break;
                    case 1:
                        chunk4 = guess.chunk4;
                        chunk3 = guess.chunk3;
                        chunk2 = guess.chunk2;
                        chunk1 = guess.chunk1;
                        bits.set(1, 0, 0, guess.carry_bits.get(1, 0, 0));
                        bits.set(1, 0, 1, guess.carry_bits.get(1, 0, 1));
                        bits.set(1, 1, 0, guess.carry_bits.get(1, 1, 0));
                        bits.set(1, 1, 1, guess.carry_bits.get(1, 1, 1));
                        break;
                    default:
                        fprintf(stderr, "Invalid guess stage!\n");
                        abort();
                        break;
                }

                bool wrong = false;
                auto zip = state->zip;
                int fileidx = 0;

                for (auto file: zip.files) {
                    auto x_array = file.random_bytes;
                    auto h_array = file.header_second;
                    const uint8_t x0 = x_array[0];
                    const uint8_t x1 = x_array[1];
                    const uint8_t x2 = x_array[2];
                    const uint8_t x3 = x_array[3];
                    const uint8_t x4 = x_array[4];
                    const uint8_t x5 = x_array[5];
                    const uint8_t x6 = x_array[6];
                    const uint8_t x7 = x_array[7];

                    const uint16_t s0 = get_s0(chunk1);
                    const uint8_t y0 = x0 ^ s0;

                    // At this point, it's really crc(k00, 0) 
                    // but gets updated to the real k0 value
                    // in step().
                    uint32_t k0 = chunk2 | (chunk6 << 8) | (chunk8 << 16) |
                        (chunk10 << 24);
                    uint32_t bound = 0;
                    uint32_t k2 = chunk1 | (chunk4 << 16) | (chunk5 << 24);

                    uint8_t s1x = step(false, chunk3, x0,
                            bits.get(1, fileidx, 0), fileidx,
                            k0, bound, k2);

                    uint8_t s2x = 0, s3x = 0, s4x = 0;
                    uint8_t s1y = 0, s2y = 0, s3y = 0, s4y = 0;
                    uint8_t y1 = 0, y2 = 0, y3 = 0, y4 = 0;

                    /* if (is_correct_guess) {
                     *  if ((x1 ^ s1x) != file.header_first[1]) {
                     *      abort();
                     *  }
                     * } */

                    if (stage == 1) goto y;

                    s2x = step(true, chunk7, x1, bits.get(2, fileidx, 0),
                            fileidx, k0, bound, k2);

                    /* if (is_correct_guess) {
                     *   if ((x2 ^ s2x) != file.header_first[2]) {
                     *    abort();
                     *   }
                     * } */

                    if (stage == 2) goto y;

                    s3x = step(true, chunk9, x2,
                            bits.get(3, fileidx, 0), fileidx,
                            k0, bound, k2);

                    /* if (is_correct_guess) {
                     *  if ((x3 ^ s3x) != file.header_first[3]) {
                     *   abort();
                     *  }
                     * } */
                    if (stage == 3) goto y;

                    s4x = step(true, chunk11, x3,
                            bits.get(4, fileidx, 0), fileidx,
                            k0, bound, k2);
                    /* if (is_correct_guess) {
                     *  if ((x4 ^ s4x) != file.header_first[4]) {
                     *   abort();
                     *  }
                     * } */
                    if (stage == 4) goto y;

                    // TOD0(stay): more stages here
y:
                    k0 = chunk2 | (chunk6 << 8) | (chunk8 << 16) |
                        (chunk10 << 24);

                    bound = 0;
                    k2 = chunk1 | (chunk4 << 16) | (chunk5 << 24);

                    s1y = step(false, chunk3, y0,
                            bits.get(1, fileidx, 1), fileidx,
                            k0, bound, k2);

                    y1 = x1 ^ s1x;
                    if ((y1 ^ s1y) != file.header_second[1]) {
                        wrong = true;
                        break;
                    }

                    if (stage == 1) goto done;

                    s2y = step(true, chunk7, y1,
                            bits.get(2, fileidx, 1), fileidx,
                            k0, bound, k2);
                    y2 = x2 ^ s2x;
                    if ((y2 ^ s2y) != file.header_second[2]) {
                        wrong = true;
                        break;
                    }
                    if (stage == 2) goto done;

                    s3y = step(true, chunk9, y2,
                            bits.get(3, fileidx, 1), fileidx,
                            k0, bound, k2);

                    y3 = x3 ^ s3x;
                    if ((y3 ^ s3y) != file.header_second[3]) {
                        wrong = true;
                        break;
                    }
                    if (stage == 3) goto done;

                    s4y = step(true, chunk11, y3,
                            bits.get(4, fileidx, 1), fileidx,
                            k0, bound, k2);

                    y4 = x4 ^ s4x;
                    if ((y4 ^ s4y) != file.header_second[4]) {
                        wrong = true;
                        break;
                    }
                    if (stage == 4) goto done;

done:
                    ++fileidx;
                }

                if (!wrong) {
                    out.push_back(guess);
                }
            } // foreach new stage guess
        } // foreach old stage guess.
        return 1;
    }

    int stage1(const crack_t* state, vector<guess_t>& out,
            const guess_t& correct_guess, uint16_t expected_s0) {
        guess_t candidate(1);
        vector<guess_t> in;
        in.push_back(candidate);
        return next(1, state, in, out);
    }

    int stage2(const crack_t* state, const vector<guess_t> in,
            vector<guess_t>& out, const guess_t& correct_guess,
            uint16_t expected_s0) {
        return next(2, state, in, out);
    }

    int stage3(const crack_t* state, const vector<guess_t>& in,
            vector<guess_t>& out) {
        return next(3, state, in, out);
    }


    int stage4(const crack_t* state, const vector<guess_t> in,
            vector<guess_t> out) {
        return next(4, state, in, out);
    }

    int stage5(const crack_t* state, const vector<guess_t> in,
            vector<guess_t> out) {
        return next(5, state, in, out);
    }

    int stage6(const crack_t* state, const vector<guess_t> in,
            vector<guess_t> out) {
        return next(6, state, in, out);
    }

    int stage7(const crack_t* state, const vector<guess_t> in,
            vector<guess_t> out) {
        return next(7, state, in, out);
    }

}; // namespace
