/***
 * Author: Nash E. Foster <leaf@pyrofex.net>
 */

#include <vector>
#include <array>
#include <cstdint>
#include <tuple>

#pragma pack(1)

namespace breakzip {

    using namespace std;

    /* There are 4 stages with 2 carry bits per stage, one for each file. */
    typedef std::array<std::array<bool, 2>, 4> carrybits_t;


    class guess_t {
        public:
            uint16_t chunk1;
            uint8_t chunk2;
            uint8_t chunk3;
            uint8_t chunk4;
            uint8_t chunk5;
            uint8_t chunk6;
            uint8_t chunk7;
            carrybits_t carry_bits;

            explicit guess_t() :
                chunk1(0), chunk2(0), chunk3(0), chunk4(0), chunk5(0),
                chunk6(0), chunk7(0), carry_bits({{{0,0},{0,0},{0,0},{0,0}}}),
                internal_carry_bit_(0) {};

            guess_t(int chunk1) : 
                chunk1(chunk1), chunk2(0), chunk3(0), chunk4(0), chunk5(0),
                chunk6(0), chunk7(0), carry_bits({{{0,0},{0,0},{0,0},{0,0}}}),
                internal_carry_bit_(0) {};

            guess_t(uint16_t c1, uint8_t c2, uint8_t c3,
                    uint8_t c4, carrybits_t carry_bits) :
                chunk1(c1), chunk2(c2), chunk3(c3), chunk4(c4),
                chunk5(0), chunk6(0), chunk7(0), carry_bits(carry_bits) {};

            guess_t(const guess_t& other) :
                chunk1(other.chunk1), chunk2(other.chunk2),
                chunk3(other.chunk3), chunk4(other.chunk4),
                chunk5(other.chunk5), chunk6(other.chunk6),
                chunk7(other.chunk7), carry_bits(other.carry_bits) {}

            std::string str() {
                char cstr[64];
                snprintf(cstr, 64, "%d-%d-%d-%d-%d-%d-%d", chunk7, chunk6,
                        chunk5, chunk4, chunk3, chunk2, chunk1);

                std::string ret(cstr);
                return std::move(ret);
            }

            std::string hex() const {
                char cstr[64];
                snprintf(cstr, 64, "0x%08x%04x%04x%04x%04x%04x%04x",
                        chunk7, chunk6, chunk5, chunk4, chunk3, chunk2, chunk1);

                std::string ret(cstr);
                return std::move(ret);
            }

            bool operator==(const guess_t& other) const {
                return (this->chunk1 == other.chunk1 &&
                        this->chunk2 == other.chunk2 &&
                        this->chunk3 == other.chunk3 &&
                        this->chunk4 == other.chunk4 &&
                        this->chunk5 == other.chunk5 &&
                        this->chunk6 == other.chunk6 &&
                        this->chunk7 == other.chunk7 &&
                        this->carry_bits == other.carry_bits);
            }

            bool operator!=(const guess_t& other) { return !(*this == other); }

            guess_t& operator=(const guess_t& other) {
                if (*this != other) {
                    this->chunk1 = other.chunk1;
                    this->chunk2 = other.chunk2;
                    this->chunk3 = other.chunk3;
                    this->chunk4 = other.chunk4;
                    this->chunk5 = other.chunk5;
                    this->chunk6 = other.chunk6;
                    this->chunk7 = other.chunk7;
                    this->carry_bits = other.carry_bits;
                }
                return *this;
            }

            // This operator defines the ordering of elements. I.e., which 
            // chunks have significance. Carry bits are the least
            // significant.
            friend bool operator<(const guess_t& left, const guess_t& right) {
                return
                    std::tie(left.chunk7, left.chunk5, left.chunk4,
                            left.chunk3, left.chunk2, left.chunk1,
                            left.carry_bits[0][0], left.carry_bits[0][1],
                            left.carry_bits[1][0], left.carry_bits[1][1],
                            left.carry_bits[2][0], left.carry_bits[2][1],
                            left.carry_bits[3][0], left.carry_bits[3][1]) <
                    std::tie(right.chunk7, right.chunk5, right.chunk4,
                            right.chunk3, right.chunk2, right.chunk1,
                            right.carry_bits[0][0], right.carry_bits[0][1],
                            right.carry_bits[1][0], right.carry_bits[1][1],
                            right.carry_bits[2][0], right.carry_bits[2][1],
                            right.carry_bits[3][0], right.carry_bits[3][1]);

            }

            friend bool operator>(const guess_t& left, const guess_t& right) {
                return right < left;
            }

            friend bool operator<=(const guess_t& left, const guess_t& right) {
                return !(left > right);
            }

            friend bool operator>=(const guess_t& left, const guess_t& right) {
                return !(left < right);
            }

            guess_t& operator*() { return *this; }

            bool compare(const guess_t& other) const {
                return (this->chunk1 == other.chunk1 &&
                        this->chunk2 == other.chunk2 &&
                        this->chunk3 == other.chunk3 &&
                        this->chunk4 == other.chunk4 &&
                        this->chunk5 == other.chunk5 &&
                        this->chunk6 == other.chunk6 &&
                        this->chunk7 == other.chunk7 &&
                        this->carry_bits[0][0] == other.carry_bits[0][0] &&
                        this->carry_bits[0][1] == other.carry_bits[0][1] &&
                        this->carry_bits[1][0] == other.carry_bits[1][0] &&
                        this->carry_bits[1][1] == other.carry_bits[1][1] &&
                        this->carry_bits[2][0] == other.carry_bits[2][0] &&
                        this->carry_bits[2][1] == other.carry_bits[2][1] &&
                        this->carry_bits[3][0] == other.carry_bits[3][0] &&
                        this->carry_bits[3][1] == other.carry_bits[3][1]);
            }

            /* In stage1, a guess compares equal if the stage1 chunks and stage1
             * carry bits are equal.
             */
            bool stage1_compare(const guess_t& other) const {
                return (this->chunk1 == other.chunk1 &&
                        this->chunk2 == other.chunk2 &&
                        this->chunk3 == other.chunk3 &&
                        this->chunk4 == other.chunk4 &&
                        this->carry_bits[0][0] == other.carry_bits[0][0] &&
                        this->carry_bits[0][1] == other.carry_bits[0][1]);
            }

            /* In stage2, a guess compares equal if they're equal in stage1 and the
             * stage2 chunks and carry bits are equal.
             */
            bool stage2_compare(const guess_t& other) const {
                return (this->stage1_compare(other) &&
                        this->chunk5 == other.chunk5 &&
                        this->chunk6 == other.chunk6 &&
                        this->chunk7 == other.chunk7 &&
                        this->carry_bits[1][0] == other.carry_bits[1][0] &&
                        this->carry_bits[1][1] == other.carry_bits[1][1]);
            }

            // Prefix increment.
            guess_t& operator++() {
                // TODO(leaf): Handle iterating over carry bits.
                if (UINT16_MAX != chunk1) { ++(this->chunk1); return *this; }

                // chunk1 was MAX, so it's carrying. Set to 0 and continue.
                this->chunk1 = 0;

                if (UINT8_MAX != chunk2) {
                    // chunk2 doesn't carry. 
                    ++(this->chunk2);
                    return *this;
                }

                this->chunk2 = 0;
                if (UINT8_MAX != chunk3) {
                    // chunks1 and 2 carry, but not 3.
                    ++(this->chunk3);
                    return *this;
                }

                this->chunk3 = 0;
                if (UINT8_MAX != chunk4) {
                    ++(this->chunk4);
                    return *this;
                }

                this->chunk4 = 0;
                if (UINT8_MAX != chunk5) {
                    ++(this->chunk5);
                    return *this;
                }

                this->chunk5 = 0;
                if (UINT8_MAX != chunk6) {
                    ++(this->chunk6);
                    return *this;
                }

                this->chunk6 = 0;
                if (UINT8_MAX != chunk7) {
                    ++(this->chunk7);
                    return *this;
                }

                // everything carries, roll over to 0 but mark the carry bit.
                this->chunk7 = 0;
                this->internal_carry_bit_ = 1;
                return *this;
            }

        private:
            uint8_t internal_carry_bit_;
    };


    /* Structure for containing the global state of the cracking job on this
     * thread.
     */
    typedef struct zip_cryptfile {
        uint8_t random_bytes[10];
        uint8_t header_first[10];
        uint8_t header_second[10];
    } zip_cryptfile_t;

    typedef struct zip_crack {
        pid_t pid;
        time_t time;
        unsigned int seed;
        std::array<uint32_t, 3> keys;
        // TODO(leaf): Because the specific target archive for which we're
        // writing this crack has only two files, we hard-coded that number
        // here. To make this attack generally useful, we would need a vector
        // here instead.
        std::array<zip_cryptfile_t, 2> files;
    } zip_crack_t;

    typedef struct crack {
        guess_t stage1_start;
        guess_t stage1_end;

        guess_t stage2_start;
        guess_t stage2_end;

        zip_crack_t zip;
    } crack_t;

    /* Helper functions for testing stage1. */
    guess_t stage1_correct_guess(crack_t crypt_test);
    guess_t stage1_correct_guess_start(guess_t correct_guess);
    guess_t stage1_correct_guess_end(guess_t correct_guess);

    /* Helper functions for testing stage2. */
    guess_t stage2_correct_guess(const crack_t crack_test);


    class stage1_range {
        // Iteration for stage1 is over chunks 1-4 with 4 carry bits. We
        // pack those into 64-bits to implement the iterator as follows:
        //
        //   carry1y: bool    (0)
        //   carry1x: bool    (1)
        //   carry0y: bool    (2)
        //   carry0x: bool    (3)
        //   chunk4: uint8_t  (4-11)
        //   chunk3: uint8_t  (12-19)
        //   chunk2: uint8_t  (20-27)
        //   chunk1: uint16_t (28-43)
        //
        // The iterator always starts with carry bits 0, you can't specify
        // a start/end for carry bits as part of the iterator.

        public:
            explicit stage1_range(const crack_t& state) : state_(state) {};

            guess_t begin() {
                return guess_t(state_.stage1_start);
            }

            guess_t end() {
                return guess_t(state_.stage1_end);
            }

        private:
            const crack_t& state_;
    };




    // Notation:
    // 
    // key00, key10, key20 are the keys after having processed the password.
    // Bytes produced by rand() are x0, x1, x2, ...
    // Stream bytes during first encryption are s0, s1x, s2x, ...
    // key0nx, key1nx, key2nx are the keys after having processed the password and
    // the first n bytes of x.
    //
    // y0 = x0 ^ s0, y1 = x1 ^ s1x, y2 = x2 ^ s2x, ...
    // Stream bytes during second encryption are s0, s1y, s2y, ...
    // Header bytes in zip file are h0 = y0 ^ s0 = x0, h1 = y1 ^ s1y, h2 = y2 ^ s2y, ...
    // key0ny, key1ny, key2ny are the keys after having processed the password and the
    // first n bytes of y.
    // 
    // stage 1:
    // 
    // We guess [chunk1 = bits 0..15 of key20 (16 bits)] 
    // We guess [chunk2 = LSB(CRC(key00, 0)) (8 bits)]
    // We guess [chunk3 = MSB(key10 * 0x08088405), carry for x, carry for y (10 bits)]
    // We guess [chunk4 = bits 16..23 of key20 (8 bits)]
    //    - note if chunk4 is a uint32_t then the bits should be in the correct
    //    position, otherwise you have to bitshift them before combining with chunk1
    //    during the computation of s1x below.
    // (42 bits total)
    // 
    // From chunk1 we compute s0 as follows:
    //      temp = key20 | 3;
    //      s0 = ((temp * (temp ^ 1)) >> 8) & 0xff;
    // For each file, get x0 from the header.
    // From that and chunk2 we compute:
    //      temp = crctab[x0] & 0xff;
    //      temp ^= chunk2
    //      temp *= 0x08088405
    //      temp = (temp + 1) >> 24;
    // From that and chunk3 we compute MSB(key11x):
    //      MSB(key11x) = temp + chunk3 + carry for x
    // From that and chunk4 we compute s1x:
    //      r = chunk4 | chunk1
    //      key21x_low24bits = crc32(r, MSB(key11x))
    //      temp = key21x_low24bits | 3;
    //      s1x = ((temp * (temp ^ 1)) >> 8 & 0xff
    //           
    // y0 = x0 ^ s0
    // From that and chunk2 we compute LSB(key01y) * 0x08088405 + 1
    //      temp = crctab[y0] & 0xff;
    //      temp ^= chunk2
    //      temp *= 0x08088405
    //      temp = (temp + 1) >> 24;
    // From that and chunk3 we compute MSB(key11y):
    //      MSB(key11y) = temp + chunk3 + carry for y
    // From that and chunk4 we compute s1y
    //      r = chunk4 | chunk1
    //      key21y_low24bits = crc32(r, MSB(key11y))
    //      temp = key21y_low24bits | 3;
    //      s1y = ((temp * (temp ^ 1)) >> 8 & 0xff
    // 
    // We compute x1 ^ s1x ^ s1y and compare it to h1.  If it's wrong, our guess was wrong.
    // 
    // We get 16 bits of filter from h1 in each of the two files.
    // We expect 2**{42 - 16} = 2**26 chunk1-4 tuples to pass.


    /***
     * stage1: begin with guess start and continue guessing until end. Each guess that
     * passes is placed into the output vector. Returns 1 if no error occurred. When
     * errors happen, returns 0 and sets errno.
     */

    int stage1(const crack_t* state, vector<guess_t>& out,
            const guess_t& correct_guess=0, uint16_t expected_s0=0);

    // stage 2:

    // We guess [chunk5 = bits 24..32 of key20 (8 bits)]
    // We guess [chunk6 = bits 16..23 of key00 (8 bits)]
    // We guess [chunk7 = MSB(key10 * 0xD4652819), carry for x,
    // carry for y (10 bits)]
    // (26 bits total)

    // Similar process as before, but filtering with h2 in each file.  (I'll
    // flesh this out later.)  We expect 2**{26 + 25 - 16} = 2**{35} chunk1-7
    // tuples to pass, 2**{26 + 25} = 2**51 work where the 26 in the exponent
    // is from stage 1 and the 25 from stage 2.


    /* stage2 depends on guesses from stage1. Each guess from the in vector
     * is used to generate a series of additional guesses. Each guess that
     * passed stage 1 will get 2^26 guesses in this stage. A guess that passes
     * stage2 will include 42 bits from stage 1 as a 64-bit integer and 26 bits
     * from stage2 as a 32-bit integer.
     */

    int stage2(const crack_t* state, const vector<guess_t> in,
            vector<guess_t>& out,
            uint64_t correct_guess=0, uint16_t expected_s0=0);

    // stage 3:
    // We guess [chunk8 = bits 24..32 of key00 (8 bits)]
    // We guess [chunk9 = MSB(key10 * 0x576eac7d), carry for x, carry for y (10
    // bits)]
    // (18 bits total)

    // Similar process as before, but filtering with h3 in each file.  We
    // expect 2**{35 + 18 - 16} = 2**{37} chunk1-9 tuples to pass, 2**{35 + 18}
    // = 2**53 work where the 35 in the exponent is from stage 2 and the 18
    // from stage 3.

    /*
     * stage3 depends on guesses from stage2. 
     */
    int stage3(const crack_t* state, const vector<guess_t> in,
            vector<guess_t> out);


    // stage 4:
    // We guess [chunk10 = bits 0..7 of key00 (8 bits)]
    // We guess [chunk11 = MSB(key10 * 0x1201d271), carry for x, carry for y (10 bits)]
    // (18 bits total)

    // Similar process as before, but filtering with h3 in each file.  We
    // expect 2**{37 + 18 - 16} = 2**{39} chunk1-11 tuples to pass, 2**{37 +
    // 18} = 2**55 work where the 37 in the exponent is from stage 3 and the 18
    // from stage 4.

    int stage4(const crack_t* state, const vector<guess_t> in,
            vector<guess_t> out);

    // 
    // stage 5:
    // No guesses, just filtration with h4 in each file.  
    // We expect 2**{38 - 16} = 2**{22} chunk1-11 tuples to pass, 2**38 work
    // where the 38 in the exponent is from stage 4.
    int stage5(const crack_t* state, const vector<guess_t> in,
            vector<guess_t> out);

    // 
    // stage 6:
    // No guesses, just filtration with h5 in each file.  
    // We expect 2**{22 - 16} = 2**{6} chunk1-11 tuples to pass, 2**22 work
    // where the 22 in the exponent is from stage 5.
    int stage6(const crack_t* state, const vector<guess_t> in,
            vector<guess_t> out);

    // 
    // stage 7:
    // No guesses, just filtration with h5 in each file.  
    // We expect 2**{6 - 16} = 2**{-10} chunk1-11 tuples to pass, 2**6 work
    // i.e. only the right one, where the 6 in the exponent is from stage 6.
    // 
    int stage7(const crack_t* state, const vector<guess_t> in,
            vector<guess_t> out);

}; // namespace
