/***
 * Author: Nash E. Foster <leaf@pyrofex.net>
 */

#include "stages.h"

#include <algorithm>

#define CGPRINT(x, ...) if ((correct_guess != 0) && (guess_bits == correct_guess)) { \
    fprintf(stderr, x, __VA_ARGS__); \
}
#define CGABORT(x, ...) if ((correct_guess != 0) && (guess_bits == correct_guess)) { \
    fprintf(stderr, x, __VA_ARGS__); \
    abort(); \
}
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

    uint64_t stage1_correct_guess(const crack_t crypt_test) {
        const uint32_t k00 = crypt_test.zip.keys[0];
        const uint32_t k10 = crypt_test.zip.keys[1];
        const uint32_t k20 = crypt_test.zip.keys[2];

        DPRINT("Keys: 0x%x 0x%x 0x%x\n", k00, k10, k20);

        const uint16_t chunk1  = k20 & 0xffff;
        const uint8_t  chunk2  = ((k00 >> 8) ^ crc32tab[k00 & 0xff]) & 0xff;
        const uint16_t chunk3  = (k10 * 0x08088405) >> 24;
        const uint8_t chunk4 = (k20 >> 16) & 0xff;

        uint8_t carry_bits[2][2];

        const auto zip = crypt_test.zip;
        int fileidx = 0;
        for (auto file: zip.files) {
            const uint8_t x0 = file.random_bytes[0];

            const uint32_t crcx0   = crc32tab[x0];
            const uint8_t  lsbk01x = (chunk2 ^ crcx0) & 0xff;
            const uint32_t low24x  = (lsbk01x * 0x08088405 + 1) & 0x00ffffff;
            carry_bits[fileidx][0] =
                (low24x + ((k10 * 0x08088405) & 0x00ffffff)) >= (1 << 24);

            const uint16_t temp1x  = (k20 | 3) & 0xffff;
            const uint8_t  s0      = ((temp1x * (temp1x ^ 1)) >> 8) & 0xff;
            const uint8_t  y0      = x0 ^ s0;
            const uint32_t crcy0   = crc32tab[y0];
            const uint8_t  lsbk01y = (chunk2 ^ crcy0) & 0xff;
            const uint32_t low24y  = (lsbk01y * 0x08088405 + 1) & 0x00ffffff;
            carry_bits[fileidx][1] =
                (low24y + ((k10 * 0x08088405) & 0x00ffffff)) >= (1 << 24);

            ++fileidx;
        }

        uint64_t rval = 0;
        rval |= (uint64_t)chunk1;
        rval |= (uint64_t)chunk2 << 16;
        rval |= (uint64_t)chunk3 << 24;
        rval |= (uint64_t)chunk4 << 32;
        rval |= (uint64_t)(carry_bits[0][0]) << 40;
        rval |= (uint64_t)(carry_bits[0][1]) << 41;
        rval |= (uint64_t)(carry_bits[1][0]) << 42;
        rval |= (uint64_t)(carry_bits[1][1]) << 43;
        return rval;
    }

    uint64_t stage1_correct_guess_start(uint64_t correct_guess) {
        return correct_guess & ~ 0xffff;
    }

    uint64_t stage1_correct_guess_end(uint64_t correct_guess) {
        return correct_guess | 0xffff;
    }

    uint32_t stage2_correct_guess(const crack_t crypt_test) {
        const uint32_t k00 = crypt_test.zip.keys[0];
        const uint32_t k10 = crypt_test.zip.keys[1];
        const uint32_t k20 = crypt_test.zip.keys[2];
        DPRINT("Keys: 0x%x 0x%x 0x%x\n", k00, k10, k20);

        const uint16_t chunk1  = k20 & 0xffff;
        const uint8_t  chunk2  = ((k00 >> 8) ^ crc32tab[k00 & 0xff]) & 0xff;
        const uint16_t chunk3  = (k10 * 0x08088405) >> 24;
        const uint8_t chunk4 = (k20 >> 16) & 0xff;
        const uint8_t chunk5 = (k20 >> 24) & 0xff;
        const uint8_t chunk6 = (crc32(k00, 0) >> 8) & 0xff;

        uint8_t carry_bits[2][2];
        uint8_t stage1_carry_bits[2][2];
        const auto zip = crypt_test.zip;
        int fileidx = 0;

        uint8_t chunk7 = 0;
        for (auto file: zip.files) {
            const uint8_t x0 = file.random_bytes[0];
            const uint8_t x1 = file.random_bytes[1];

            const uint8_t key01x = crc32(k00, x0);
            const uint8_t key11x = (k10 + (key01x & 0xff)) * 0x08088405 + 1;

            const uint32_t key02x = crc32(key01x, x1);
            const uint8_t t1  = (key02x & 0xff) * 0x08088405 + 1;
            const uint32_t t2 = key11x * 0x08088405;
            const uint8_t carry_for_x =
                (t1 & 0xffffff) + (t2 & 0xffffff) >= (1L<<24);

            const uint8_t maybe_chunk7 = (k10 * 0xf4652819) >> 24;

            if (0 == fileidx) {
                chunk7 = maybe_chunk7;
            } else if (chunk7 != maybe_chunk7) {
                fprintf(stderr, "FATAL ERROR: chunk7 calculation failed, got different "
                        "results from each file: %d != %d\n",
                        chunk7, maybe_chunk7);
                abort();
            }

            ++fileidx;
        }

        uint32_t rval = 0;
        rval |= (uint64_t)chunk5;
        rval |= (uint64_t)chunk6 << 8;
        rval |= (uint64_t)chunk7 << 16;
        rval |= (uint64_t)(carry_bits[0][0]) << 24;
        rval |= (uint64_t)(carry_bits[0][1]) << 25;
        rval |= (uint64_t)(carry_bits[1][0]) << 26;
        rval |= (uint64_t)(carry_bits[1][1]) << 27;
        return rval;
    }

    void set_bound_from_carry_bit(const bool carry_bit,
            const uint32_t lowbits, uint32_t* upper, uint32_t* lower) {
        if (nullptr == upper || nullptr == lower) {
            fprintf(stderr, "FATAL error: null pointer in call to "
                    "set_bound_from_carry_bit. Aborting.\n");
            abort();
        }

        // Depending on the carry bit, this will either be an upper or lower bound.
        uint32_t bound = (1L << 24) - (lowbits & 0x00ffffff);

        if (carry_bit) {
            *lower = std::max(*lower, bound);
        } else {
            *upper = std::min(*upper, bound - 1);
        }
    }


    uint16_t get_s0_from_chunk1(const uint16_t chunk1) {
        const uint16_t tmp = chunk1 | 3;
        const uint16_t s0 = ((tmp * (tmp ^ 1)) >> 8) & 0xff;
        return s0;
    }

    int stage1(const crack_t* state, vector<guess_t>& out,
            uint64_t correct_guess, uint16_t expected_s0) {
        // For testing, we accept a correct_guess parameter that can be
        // used to figure out where it's being ignored, if at all.

        uint64_t guess_bits = state->stage1_start;
        while (guess_bits < state->stage1_end) {
            /**
             * Packed structure:
             *   chunk1: uint16_t (0-15)
             *   chunk2: uint8_t  (16-23)
             *   chunk3: uint8_t  (24-31)
             *   chunk4: uint8_t  (32-39)
             *   carry0x: bool    (40)
             *   carry0y: bool    (41)
             *   carry1x: bool    (42)
             *   carry1y: bool    (43)
             */

            uint16_t chunk1 = guess_bits & 0xffff;
            uint8_t chunk2 = (guess_bits >> 16) & 0xff;
            // chunk3: high 8 bits of key10 * 0x08088405.
            uint8_t chunk3 = (guess_bits >> 24) & 0xff;
            uint8_t chunk4 = (guess_bits >> 32) & 0xff;

            uint32_t upper = 0x00ffffff;
            uint32_t lower = 0;

            bool carry_bits[2][2] = {
                (bool)(guess_bits >> 40) & 0x01,
                (bool)(guess_bits >> 41) & 0x01,
                (bool)(guess_bits >> 42) & 0x01,
                (bool)(guess_bits >> 43) & 0x01
            };

            // Compute s0.
            uint16_t s0 = get_s0_from_chunk1(chunk1);

            if (correct_guess != 0 && (guess_bits == correct_guess)) {
                if ((expected_s0 & 0x100)) {
                    if (s0 != (expected_s0 & 0xff)) {
                        CGABORT("FATAL ERROR: stream byte 0 not calculated "
                                "correctly: expected 0x%x, got 0x%x, but guess is "
                                "expected(0x%lx)==guess(0x%lx)\n",
                                expected_s0 & 0xff, s0 & 0xff, correct_guess, guess_bits);
                    }
                }
            }

            bool wrong = false;

            auto zip = state->zip;
            int fileidx = 0;
            for (auto file: zip.files) {
                auto x_array = file.random_bytes;
                auto h_array = file.header_second;

                uint8_t carry_for_x = (uint8_t)carry_bits[fileidx][0];
                uint8_t carry_for_y = (uint8_t)carry_bits[fileidx][1];

                uint32_t temp = crc32tab[x_array[0]] & 0xff;
                temp ^= chunk2;
                temp *= 0x08088405;
                temp = (temp + 1) >> 24;

                // Insert bounds checking w/carry bit calculation here.
                // TODO(leaf): Confirm with Mike this new approach is right in stage1.
                set_bound_from_carry_bit(chunk2, carry_for_x, x_array[0],
                        &upper, &lower);


                uint8_t msb_key11x = temp + chunk3 + carry_for_x;
                const uint32_t key20_low24bits = (chunk4 << 16) | chunk1;
                uint32_t key21x_low24bits = crc32(key20_low24bits, msb_key11x);
                uint32_t t = key21x_low24bits | 3;
                uint8_t s1x = ((t * (t ^ 1)) >> 8) & 0xff;
                CGPRINT("correct guess: s1x(0x%x) | t(0x%x) | key21_low24(0x%x)\n",
                        s1x, t, key21x_low24bits);

                uint8_t y0 = x_array[0] ^ s0;
                // TODO(leaf): Confirm with Mike this new approach is right in stage1.
                set_bound_from_carry_bit(chunk2, carry_for_y, y0, &upper, &lower);
                if (upper < lower) {
                    // Guess is wrong. Abort.
                    wrong = true;
                    CGABORT("ERROR: upper(0x%x) < lower(0x%x) but "
                            "guess appears correct: 0x%lx == 0x%lx\n",
                            upper, lower, guess_bits, correct_guess);
                    break;
                }

                uint32_t tt = crc32tab[y0] & 0xff;
                tt ^= chunk2;
                tt *= 0x08088405;
                tt = (tt + 1) >> 24;

                uint8_t msb_key11y = (uint8_t) (tt + chunk3 + carry_for_y);
                uint32_t key21y_low24bits = crc32(key20_low24bits, msb_key11y);
                uint32_t ttt = key21y_low24bits | 3;
                uint8_t s1y = ((ttt * (ttt ^ 1)) >> 8) & 0xff;

                // NB(leaf): No parens needed because xor is commutative.
                uint8_t maybe_h1 = x_array[1] ^ s1x ^ s1y;
                CGPRINT("maybe_h1(0x%x) = x[1](0x%x) ^ s1x(0x%x) ^ s1y(0x%x)\n",
                        maybe_h1, x_array[1], s1x, s1y);
                if (maybe_h1 != h_array[1]) {
                    // Guess is wrong. Abort.
                    wrong = true;
                    CGABORT("ERROR: maybe_h1(0x%x) != h_array[1](0x%x), but "
                            "guess appears correct: 0x%lx == 0x%lx\n",
                            maybe_h1, h_array[1], guess_bits, correct_guess);
                    break;
                }

                ++fileidx;
            }

            if (!wrong) {
                // Guess passed all files, add to output list.
                guess_t ok = { guess_bits, 0, 0, 0 };
                out.push_back(ok);
            }

            guess_bits += 1;
        }

        return 1;
    }

    int stage2(const crack_t* state, const vector<guess_t> in,
            vector<guess_t>& out, uint64_t correct_guess,
            uint16_t expected_s0) {

        // For testing, we accept a correct_guess parameter that can be
        // used to figure out where it's being ignored, if at all.

        // NB(leaf): For now, stage2 begins searching at zero and proceeds
        // through all 2^28 possibilities. In future, we may need to have
        // start/end constraints like stage1 does.
        for (auto guess: in) {
            const uint16_t chunk1 = guess.stage1_bits & 0xffff;
            const uint8_t chunk2 = (guess.stage1_bits >> 16) & 0xff;
            // chunk3: high 8 bits of key10 * 0x08088405.
            const uint8_t chunk3 = (guess.stage1_bits >> 24) & 0xff;
            const uint8_t chunk4 = (guess.stage1_bits >> 32) & 0xff;

            const bool stage1_carry_bits[2][2] = {
                (bool)(guess.stage1_bits >> 40) & 0x01,
                (bool)(guess.stage1_bits >> 41) & 0x01,
                (bool)(guess.stage1_bits >> 42) & 0x01,
                (bool)(guess.stage1_bits >> 43) & 0x01
            };

            // We need to iterate over all values of uint32_t, so our index
            // variable is 64 bits.
            for (uint64_t i = 0; i < UINT32_MAX + 1; ++i) {
                // The guess is the lower 32-bits of the index downcast to a
                // 32-bit int.
                const uint32_t guess_bits = (uint32_t)(i & 0xffffffff);

                /**
                 * Packed structure:
                 *   chunk5: uint8_t (0-7)
                 *   chunk6: uint8_t (8-15)
                 *   chunk7: uint8_t (16-23)
                 *   carry0x: bool   (24)
                 *   carry0y: bool   (25)
                 *   carry1x: bool   (26)
                 *   carry2x: bool   (27)
                 */
                uint8_t chunk5 = guess_bits & 0xff;
                uint8_t chunk6 = (guess_bits >> 8) & 0xff;
                uint8_t chunk7 = (guess_bits >> 16) & 0xff;

                bool carry_bits[2][2] = {
                    (bool)(guess_bits >> 24) & 0x01,
                    (bool)(guess_bits >> 25) & 0x01,
                    (bool)(guess_bits >> 26) & 0x01,
                    (bool)(guess_bits >> 27) & 0x01
                };

                const uint32_t k20 = chunk1 | (chunk4 << 16) | (chunk5 << 24);

                bool wrong = false;
                auto zip = state->zip;
                int fileidx = 0; 
                for (auto file: zip.files) {
                    auto x_array = file.random_bytes;
                    auto h_array = file.header_second;
                    const uint8_t x0 = x_array[0];
                    const uint8_t x1 = x_array[1];
                    const uint8_t x2 = x_array[2];

                    uint32_t stage1_upper = 0x00ffffff;
                    uint32_t stage1_lower = 0;

                    uint32_t upper = 0x00ffffff;
                    uint32_t lower = 0;

                    const uint8_t stage1_carry_for_x =
                        (uint8_t)stage1_carry_bits[fileidx][0];
                    const uint8_t stage1_carry_for_y =
                        (uint8_t)stage1_carry_bits[fileidx][1];

                    const uint16_t s0 = get_s0_from_chunk1(chunk1);
                    const uint8_t y0 = x0 ^ s0;
                    const uint32_t key20 = chunk1 | (chunk4 << 16) | (chunk5 << 24);
                    const uint32_t key01x = (chunk2 | (chunk6 << 8)) ^ crc32tab[x0];
                    const uint8_t lsbkey01x = key01x & 0xff;

                    const uint32_t bound1x = lsbkey01x * 0x08088405 + 1;

                    // bounds & carries from stage 1
                    set_bound_from_carry_bit(stage1_carry_for_x, bound1x,
                            &stage1_upper, &stage1_lower);

                    const uint32_t key01x_temp = (lsbkey01x * 0x08088405 + 1) >> 24;
                    const uint8_t msb_key11x =
                        (uint8_t)(key01x_temp + chunk3 + stage1_carry_for_x);
                    const uint32_t key21x = crc32(key20, msb_key11x);
                    const uint32_t s1x_temp = (key21x | 3) & 0xffff;
                    const uint8_t s1x =
                        ((s1x_temp * (s1x_temp ^ 1)) >> 8) & 0xff;
                    const uint32_t key02x = crc32(key01x, x1);
                    const uint8_t lsbkey02x = (uint8_t) (key02x & 0xff);

                    const uint32_t bound2x =
                        lsbkey01x * 0xd4652819 + 0x08088405 +
                        lsbkey02x * 0x08088405 + 1;
                    set_bound_from_carry_bit(carry_bits[fileidx][0], bound2x,
                            &upper, &lower); // bounds & carries from stage 2

                    const uint8_t msbkey12x =
                        chunk7 + carry_bits[fileidx][0] + (bound2x >> 24);
                    const uint32_t key22x = crc32(key21x, msbkey12x);
                    const uint32_t s2x_temp = (key22x | 3) & 0xffff;
                    const uint8_t s2x =
                        ((s2x_temp * (s2x_temp ^ 1)) >> 8) & 0xff;

                    const uint32_t key01y =
                        (chunk2 | (chunk6 << 8)) ^ crc32tab[y0];
                    const uint8_t lsbkey01y = key01y & 0xff;

                    const uint32_t bound1y = lsbkey01x * 0x08088405 + 1;
                    set_bound_from_carry_bit(stage1_carry_for_y, bound1y,
                            &stage1_upper, &stage1_lower);

                    const uint32_t msbkey11y_temp =
                        (lsbkey01y * 0x08088405 + 1) >> 24;
                    const uint8_t msb_key11y =
                        (uint8_t)(key01y_temp + chunk3 + stage1_carry_for_y);

                    const uint32_t key21y = crc32(key20, msb_key11y);
                    const uint32_t s1y_temp = (key21y | 3) & 0xffff;
                    const uint8_t s1y =
                        ((s1y_temp * (s1y_temp ^ 1)) >> 8) & 0xff;
                    const uint8_t y1 = x1 ^ s1y;

                    // TODO: figure out if it's possible to check consistency
                    // with stage1_upper & lower information looking at the
                    // remainder of something mod 2^24 If not, remove the
                    // set_bounds_from_carry_bit calls for stage1

                    const uint32_t key02y = crc32(key01y, x1);
                    const uint8_t lsbkey02y = key02y & 0xff;

                    const uint32_t bound2y =
                        lsbkey01y * 0xd4652819 + 0x08088405 +
                        lsbkey02y * 0x08088405 + 1;
                    set_bound_from_carry_bit(carry_bits[fileidx][1], bound2y,
                            &upper, &lower);

                    if (upper < lower) {
                        wrong = true;
                        break;
                    }

                    uint8_t msbkey12y =
                        chunk7 + carry_bits[fileidx][1] + (bound2y >> 24);

                    const uint32_t key22y = crc32(key21y, msbkey12y);
                    const uint32_t s2y_temp = (key22y | 3) & 0xffff;
                    const uint8_t s2y =
                        ((s2y_temp * (s2y_temp ^ 1)) >> 8) & 0xff;
                    if (h_array[2] != x2 ^ s2x ^ s2y) {
                        wrong = true;
                        break;
                    }

                    ++fileidx;
                }

                if (!wrong) {
                    // Guess passed all files, add to output list.
                    guess.stage2_bits = guess_bits;
                    out.push_back(guess);
                }
            } // foreach stage2 guess
        } // foreach stage1 guess.
        return 1;
    }

    int stage3(const crack_t* state, const vector<guess_t> in, vector<guess_t> out) {
        return 1;
    }

    int stage4(const crack_t* state, const vector<guess_t> in, vector<guess_t> out) {
        return 1;
    }

    int stage5(const crack_t* state, const vector<guess_t> in, vector<guess_t> out) {
        return 1;
    }

    int stage6(const crack_t* state, const vector<guess_t> in, vector<guess_t> out) {
        return 1;
    }

    int stage7(const crack_t* state, const vector<guess_t> in, vector<guess_t> out) {
        return 1;
    }

}; // namespace
