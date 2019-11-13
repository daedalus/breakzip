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

    /* There are 4 carry bits per stage, 2 for each of 2 files.  There are 4
     * stages in which we guess carrybits, for a total of 16 carry bits. We
     * pack those into a single word as the low order 16 bits.
     * 
     * Carry bits for stage 1 are the high order 4 bits of the
     * low order 16 bits.
     */
    typedef struct carrybits {
        uint32_t bits:16;

        carrybits() : bits(0) {}
        carrybits(int x) : bits(x & 0xffff) {}
        carrybits(unsigned int x) : bits(x & 0xffff) {}
        carrybits(short unsigned int x) : bits(x & 0xffff) {}
        carrybits(const struct carrybits& other) : bits(other.bits) {}

        friend bool operator==(const struct carrybits& l,
                const struct carrybits& r) {
            return l.bits == r.bits;
        }

        friend bool operator!=(const struct carrybits& l,
                const struct carrybits& r) {
            return !(l == r);
        }

        friend bool operator<(const struct carrybits& l,
                const struct carrybits& r) {
            return l.bits < r.bits;
        }

        friend bool operator>(const struct carrybits& l,
                const struct carrybits& r) {
            return r < l;
        }

        friend bool operator<=(const struct carrybits& l,
                const struct carrybits& r) {
            return !(r > l);
        }

        friend bool operator>=(const struct carrybits& l,
                const struct carrybits& r) {
            return !(l < r);
        }

        static const uint16_t NUM_STAGES = 4;
        static const uint16_t BITS_PER_STAGE = 4;

        static const uint16_t shift_for_stage(int stage) {
            return (NUM_STAGES - stage) * 4;
        }

        uint8_t get(uint8_t stage) const {
            uint8_t r = (bits >> shift_for_stage(stage)) & 0x0f;
            return r;
        }

        uint8_t get(uint8_t stage, uint8_t file, uint8_t var) const {
            // TODO(leaf): If we can constrain file and var to never be
            // other than 0 or 1, then we can eliminate the conditionals.
            uint8_t shift_width = shift_for_stage(stage);
            shift_width += (0 == file) ? 0 : 2;
            shift_width += (0 == var) ? 0 : 1;
            uint8_t t = bits >> shift_width;
            return bits & 0x01;
        }

        uint32_t set(uint8_t stage, uint8_t val) {
            uint8_t shift_width = shift_for_stage(stage);
            uint16_t mask = 0x0f << shift_width;
            bits &= ~mask;
            bits |= (val & 0x0f) << shift_width;
            return bits;
        }

        uint32_t set(uint8_t stage, uint8_t file, uint8_t var, bool val) {
            uint8_t shift_width = shift_for_stage(stage);
            shift_width += (0 == file) ? 0 : 2;
            shift_width += (0 == var) ? 0 : 1;
            bits |= (val << shift_width);
            return bits;
        }

        const std::string& str() const {
            char buf[16];
            snprintf(buf, 16, "(0x%04x)", bits);
            std::string rval(buf);
            return std::move(rval);
        }
    } carrybits_t;

    class guess_t {
        public:
            uint16_t chunk1; // low 16 bits of k20
            uint8_t chunk2;  // low 8 bits of crc32(k00, 0)
            uint8_t chunk3;  // high 8 bits of k10 * CRYPTCONST
            uint8_t chunk4;  // bits 16..23 of k20
            uint8_t stage;

            uint8_t chunk5;
            uint8_t chunk6;
            uint8_t chunk7;
            uint8_t unused2;

            uint8_t chunk8;
            uint8_t chunk9;

            uint8_t chunk10;
            uint8_t chunk11;

            carrybits_t carry_bits;

            guess_t() :
                chunk1(0), chunk2(0), chunk3(0), chunk4(0), stage(1),
                chunk5(0), chunk6(0), chunk7(0), unused2(0xAA), chunk8(0),
                chunk9(0), chunk10(0), chunk11(0), carry_bits(0) {};

            guess_t(int n) :
                chunk1(0), chunk2(0), chunk3(0), chunk4(0), stage(n),
                chunk5(0), chunk6(0), chunk7(0), unused2(0xAA), chunk8(0),
                chunk9(0), chunk10(0), chunk11(0), carry_bits(0) {};

            guess_t(int n, const guess_t& other) :
                chunk1(other.chunk1), chunk2(other.chunk2),
                chunk3(other.chunk3), chunk4(other.chunk4), stage(n),
                chunk5(other.chunk5), chunk6(other.chunk6),
                chunk7(other.chunk7), unused2(0xAA), chunk8(other.chunk8),
                chunk9(other.chunk9), chunk10(other.chunk10),
                chunk11(other.chunk11), carry_bits(other.carry_bits) {};

            guess_t(int n, carrybits_t bits,
                    uint16_t c1=0, uint8_t c2=0, uint8_t c3=0, uint8_t c4=0,
                    uint8_t c5=0, uint8_t c6=0, uint8_t c7=0,
                    uint8_t c8=0, uint8_t c9=0, uint8_t c10=0, uint8_t c11=0) :
                chunk1(c1), chunk2(c2), chunk3(c3), chunk4(c4), stage(n),
                chunk5(c5), chunk6(c6), chunk7(c7), unused2(0xAA), chunk8(c8),
                chunk9(c9), chunk10(c10), chunk11(c11), carry_bits(bits) {};


            std::string str() const {
                char cstr[256];
                snprintf(cstr, 256,
                        "0x%04x%02x%02x%02x:%02x%02x%02x:%02x%02x:%02x%02x%s",
                        chunk1, chunk2, chunk3, chunk4, chunk5, chunk6, chunk7,
                        chunk8, chunk9, chunk10, chunk11,
                        carry_bits.str().c_str());
                std::string ret(cstr);
                return std::move(ret);
            }

            std::string hex() const { return str(); }

            bool operator==(const guess_t& other) const {
                return (this->carry_bits == other.carry_bits &&
                        this->chunk1 == other.chunk1 &&
                        this->chunk2 == other.chunk2 &&
                        this->chunk3 == other.chunk3 &&
                        this->chunk4 == other.chunk4 &&
                        this->chunk5 == other.chunk5 &&
                        this->chunk6 == other.chunk6 &&
                        this->chunk7 == other.chunk7 &&
                        this->chunk8 == other.chunk8 &&
                        this->chunk9 == other.chunk9 &&
                        this->chunk10 == other.chunk10 &&
                        this->chunk11 == other.chunk11);
            }

            friend bool operator!=(const guess_t& left,
                    const guess_t& right) {
                return !(left == right);
            }

            guess_t& operator=(const guess_t& other) {
                this->chunk1 = other.chunk1;
                this->chunk2 = other.chunk2;
                this->chunk3 = other.chunk3;
                this->chunk4 = other.chunk4;
                this->chunk5 = other.chunk5;
                this->chunk6 = other.chunk6;
                this->chunk7 = other.chunk7;
                this->chunk8 = other.chunk8;
                this->chunk9 = other.chunk9;
                this->chunk10 = other.chunk10;
                this->chunk11 = other.chunk11;
                this->carry_bits = other.carry_bits;
                return *this;
            }

            // This operator defines the ordering of elements. I.e., which 
            // chunks have what significance. Carry bits are the least
            // significant.
            friend bool operator<(const guess_t& left,
                    const guess_t& right) {
                return (

                        left.chunk1 < right.chunk1 &&
                        left.chunk2 < right.chunk2 &&
                        left.chunk3 < right.chunk3 &&
                        left.chunk4 < right.chunk4 &&
                        left.chunk5 < right.chunk5 &&
                        left.chunk6 < right.chunk6 &&
                        left.chunk7 < right.chunk7 &&
                        left.chunk8 < right.chunk8 &&
                        left.chunk9 < right.chunk9 &&
                        left.chunk10 < right.chunk10 &&
                        left.chunk11 < right.chunk11 &&

                        left.carry_bits < right.carry_bits);
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
                return *this == other;
            }

            // Prefix increment.
            guess_t& operator++() {
                switch (stage) {
                    case 1:
                        {

                            uint8_t s1bits = carry_bits.get(1);
                            s1bits++;
                            if (0x10 > s1bits) {
                                carry_bits.set(1, s1bits);
                                return *this;
                            }

                            carry_bits.set(1, 0);

                            if (UINT16_MAX != chunk1) {
                                ++(chunk1);
                                return *this;
                            }

                            chunk1 = 0;

                            if (UINT8_MAX != chunk2) {
                                ++(chunk2);
                                return *this;
                            }

                            chunk2 = 0;
                            if (UINT8_MAX != chunk3) {
                                ++(chunk3);
                                return *this;
                            }

                            chunk3 = 0;
                            if (UINT8_MAX != chunk4) {
                                ++(chunk4);
                                return *this;
                            }

                            chunk4 = 0;
                            return *this;
                        }
                    case 2:
                        {
                            uint8_t s2bits = carry_bits.get(2);
                            s2bits++;
                            if (0x10 > s2bits) {
                                carry_bits.set(2, s2bits);
                                return *this;
                            }

                            carry_bits.set(2, 0);

                            if (UINT8_MAX != chunk5) {
                                ++(chunk5);
                                return *this;
                            }

                            chunk5 = 0;
                            if (UINT8_MAX != chunk6) {
                                ++(chunk6);
                                return *this;
                            }

                            chunk6 = 0;
                            if (UINT8_MAX != chunk7) {
                                ++(chunk7);
                                return *this;
                            }

                            chunk7 = 0;
                            return *this;
                        }
                    case 3:
                        {
                            uint8_t s3bits = carry_bits.get(3);
                            s3bits++;
                            if (0x10 > s3bits) {
                                carry_bits.set(3, s3bits);
                                return *this;
                            }

                            carry_bits.set(3, 0);

                            if (UINT8_MAX != chunk8) {
                                ++(chunk8);
                                return *this;
                            }

                            chunk8 = 0;
                            if (UINT8_MAX != chunk9) {
                                ++(chunk9);
                                return *this;
                            }

                            chunk9 = 0;
                            return *this;
                        }
                    case 4:
                        {
                            uint8_t s4bits = carry_bits.get(4);
                            s4bits++;
                            if (0x10 > s4bits) {
                                carry_bits.set(4, s4bits);
                                return *this;
                            }

                            carry_bits.set(4, 0);

                            if (UINT8_MAX != chunk10) {
                                ++(chunk10);
                                return *this;
                            }

                            chunk10 = 0;
                            if (UINT8_MAX != chunk11) {
                                ++(chunk11);
                                return *this;
                            }

                            chunk11 = 0;
                            return *this;
                        }
                    default:
                        {
                            fprintf(stderr, "FATAL ERROR: Invalid guess stage %d "
                                    "during increment.\n", stage);
                            abort();
                        }
                }
            }
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
        uint8_t stage;
        guess_t start;
        guess_t end;
        zip_crack_t zip;
    } crack_t;

    /* Helper functions for testing stage1. */
    guess_t stage1_correct_guess(crack_t crypt_test);
    guess_t stage1_correct_guess_start(guess_t correct_guess);
    guess_t stage1_correct_guess_end(guess_t correct_guess);

    /* Helper functions for testing stage2. */
    guess_t stage2_correct_guess(const crack_t crack_test);
    guess_t stage2_correct_guess_start(guess_t correct_guess);
    guess_t stage2_correct_guess_end(guess_t correct_guess);

    class stage_range {
        public:
            explicit stage_range(int stage, const crack_t& state) :
                stage_(stage), state_(state) {};
            guess_t begin() { return guess_t(stage_, state_.start); }
            guess_t end() { return guess_t(stage_, state_.end); }

        private:
            const int stage_;
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
    // We guess [chunk2 = bits 0..7 of crc32(key00, 0) (8 bits)]
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
    // We guess [chunk6 = bits 8..15 of crc32(key00, 0) (8 bits)]
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
            const guess_t& correct_guess=0, uint16_t expected_s0=0);

    // stage 3:
    // We guess [chunk8 = bits 16..23 of crc32(key00, 0) (8 bits)]
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
    // We guess [chunk10 = bits 24..32 of crc32(key00, 0) (8 bits)]
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
