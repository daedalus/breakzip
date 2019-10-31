/* Copyright (c) 2016, Pyrofex Corporation.
 * All right reserved.
 * Author: Nash E. Foster <leaf@pyrofex.com>
 */
#include <iostream>
#include <stdlib.h>
#include <check.h>
#include <string>

#include <gflags/gflags.h>

#include "../breakzip.h"
#include "../stages.h"

using namespace breakzip;
using namespace std;


/* Our tests are based on ZIP files created with 2 files in each one. These
 * were then encrypted by an instrumented version of zipcloak with simple
 * passwords. The bytes below correspond to the internal states of various
 * encryption variables relevant to the crack.
 *
 * Note on structure: See stages.h. A crack_t contains a start, end, and a
 * single zip_crack_t. The zip_crack_t contains data about the zip archive
 * being cracked. That structure contains crypto variables and one or more
 * zip_cryptfile_t's, which are the actual encrypted files and their associated
 * crypto state data.
 */
std::array<crack_t, 10> crypt_tests = {{
    { 0, 0, 0, 0,
        { 13426, 1570546266, 1570543144, {{ 0xe4858bae, 0xa8254576, 0x3743e7bb }},
            {{{ // 1st file
                  { 0x0d, 0x33, 0xb6, 0x64, 0x5e, 0x66, 0xc0, 0x02, 0xfe, 0x13 }, // rand
                  { 0x17, 0x44, 0xd0, 0xe8, 0x08, 0x48, 0x09, 0x89, 0x1d, 0x5f }, // 1st
                  { 0x0d, 0xde, 0x72, 0xc2, 0x22, 0x5e, 0xaf, 0x75, 0x8a, 0x6c }, // 2nd
              },
            { // 2nd file
                { 0x4e, 0x8a, 0x3c, 0x9a, 0x72, 0x23, 0x41, 0xbe, 0xab, 0xb0 }, // rand
                { 0x54, 0x34, 0xf2, 0x0b, 0x6b, 0x08, 0x3d, 0x17, 0xb2, 0xbf }, // 1st
                { 0x4e, 0xc3, 0x69, 0xf4, 0x97, 0x6e, 0x5a, 0x66, 0x77, 0xcb }, // 2nd
            }}}}},
    { 0, 0, 0, 0,
        { 13428, 1570546267, 1570543151, {{ 0x1e096225, 0xcb831619, 0x296e7f2b }},
            {{{ // 1st file
                  { 0x20, 0x95, 0x07, 0xa5, 0xb9, 0x4c, 0x99, 0xcc, 0xe7, 0x4a }, // rand
                  { 0x12, 0x27, 0x02, 0xf6, 0x62, 0xe7, 0x23, 0xfc, 0x18, 0xb5 }, // 1st
                  { 0x20, 0x7e, 0xbd, 0xf1, 0xb2, 0x4e, 0xd9, 0xea, 0xa9, 0xc6 }, // 2nd
              },{ // 2nd file
                  { 0x3d, 0xff, 0x6c, 0xe0, 0x91, 0xbf, 0xc2, 0x2b, 0xca, 0x90 }, // rand
                  { 0x0f, 0xe4, 0xa7, 0x4a, 0x4d, 0x82, 0x82, 0x1e, 0xc9, 0x57 }, // 1st
                  { 0x3d, 0x4c, 0xed, 0x9f, 0x49, 0xf9, 0x78, 0x53, 0xee, 0x14 }, // 2nd
              }}}}},
    { 0, 0, 0, 0, 
        { 13429, 1570546269, 1570543144, {{ 0x10d2ea17, 0x5b0bddd3, 0xd961ec6f }},
            {{{ // 1st file
                  { 0x0d, 0x33, 0xb6, 0x64, 0x5e, 0x66, 0xc0, 0x02, 0xfe, 0x13 }, // rand
                  { 0xe6, 0x7b, 0xe8, 0x2f, 0x3f, 0x97, 0x6f, 0x26, 0x37, 0x08 }, // 1st
                  { 0x0d, 0xe0, 0xad, 0xc9, 0x9d, 0x97, 0x57, 0x7b, 0x1d, 0x94 }, // 2nd
              },{ // 2nd file
                  { 0x4e, 0x8a, 0x3c, 0x9a, 0x72, 0x23, 0x41, 0xbe, 0xab, 0xb0 }, // rand
                  { 0xa5, 0x74, 0x9c, 0x7d, 0x0d, 0xd4, 0xc2, 0x91, 0x55, 0xda }, // 1st
                  { 0x4e, 0x79, 0x47, 0x98, 0x38, 0x78, 0x26, 0x57, 0x49, 0x9a }, // 2nd
              }}}}},
    { 0, 0, 0, 0,
        { 13430, 1570546271, 1570543145, {{ 0x7d9315a2, 0xfa9f7fba, 0x15be19ef }},
            {{{ // 1st file
                  { 0x56, 0x28, 0xf7, 0x7d, 0xf8, 0x4e, 0x9a, 0x32, 0x38, 0x8b }, // rand
                  { 0x25, 0x37, 0x5c, 0xe3, 0xf0, 0x2e, 0x3c, 0x25, 0x11, 0x55 }, // 1st
                  { 0x56, 0x01, 0x88, 0x79, 0x3f, 0x36, 0x44, 0xbb, 0xdf, 0x02 }, // 2nd
              },{ // 2nd file
                  { 0x9a, 0x88, 0x62, 0x14, 0xa5, 0x6b, 0xf8, 0x2c, 0x58, 0x05 }, // rand
                  { 0xe9, 0xc5, 0xb5, 0x58, 0x15, 0xf3, 0x00, 0xad, 0xf8, 0x13 }, // 1st
                  { 0x9a, 0x6a, 0xed, 0xae, 0x4d, 0x27, 0x0a, 0x16, 0xe8, 0x45 }, // 2nd
              }}}}},
    // passwd: wobble
    { 0, 0, 0, 0, 
        { 9029, 1570650276, 1570642913, {{ 0x407b7258, 0xdd852762, 0x7dd9ef3f }},
            {{{ // 1st file
                  //init_keys[0]: 0: 0x3ff57daf 1: 0xc4ca8c56 2: 0x2a12f27b
                  { 0xfe, 0xd5, 0x3e, 0x4a, 0x4b, 0xb0, 0x67, 0x13, 0x05, 0xbf }, // rand
                  { 0x3c, 0x01, 0x02, 0x5b, 0xed, 0x81, 0x05, 0x29, 0xfe, 0x1e }, // 1st
                  //init_keys[0]: 0: 0x4a9fde33 1: 0xe0aa99ea 2: 0x161116aa
                  { 0xfe, 0xbe, 0x8c, 0x3d, 0x94, 0x53, 0x68, 0x4d, 0x5f, 0xef }, // 2nd
              },{ // 2nd file
                  //init_keys[0]: 0: 0xacfc8232 1: 0xd8a215e5 2: 0x3e13ae34
                  { 0x73, 0x3c, 0x64, 0x26, 0x70, 0x9b, 0xe0, 0xa3, 0x2e, 0x24 }, // rand
                  { 0xb1, 0x1d, 0x08, 0xa6, 0x21, 0x51, 0xe8, 0x98, 0x5f, 0x14 }, // 1st
                  //init_keys[0]: 0: 0xd99621ae 1: 0xbcc20851 2: 0x74cc0b75
                  { 0x73, 0x78, 0x52, 0x60, 0x3a, 0x6b, 0x83, 0x06, 0x97, 0x48 }, // 2nd
              }}}}},
    { 0, 0, 0, 0, 
        { 13431, 1570546274, 1570543125, {{ 0x31dc1008, 0x64feafb1, 0x2f4333bb }},
            {{{ // 1st file
                  { 0xc0, 0xa5, 0x7e, 0x9b, 0x5f, 0xb4, 0x19, 0x01, 0xe4, 0xc1 }, // rand
                  { 0x16, 0xeb, 0x03, 0x31, 0x30, 0x86, 0x47, 0x29, 0x05, 0xaf }, // 1st
                  { 0xc0, 0xaf, 0xbd, 0xa9, 0xcf, 0x4c, 0xbe, 0xf9, 0x71, 0x6c }, // 2nd
              },{ // 2nd file
                  { 0x03, 0xb1, 0xb4, 0x65, 0x91, 0xde, 0x77, 0x18, 0xfd, 0x6f }, // rand
                  { 0xd5, 0xa4, 0x97, 0x37, 0x1c, 0x69, 0x28, 0xfd, 0x8d, 0xda }, // 1st
                  { 0x03, 0xcb, 0xca, 0xf1, 0xba, 0x52, 0xff, 0x94, 0xd6, 0x26 }, // 2nd
              }}}}},
    { 0, 0, 0, 0, 
        { 12431, 1570651783, 1570639368, {{ 0x348e6771, 0xcecf3c76, 0x51a09805 }},
            {{{ // 1st file
                  { 0x3d, 0xa4, 0x0d, 0xb5, 0x8b, 0xfe, 0xde, 0xb6, 0x08, 0x50, }, // rand
                  { 0x85, 0x3d, 0x18, 0x6a, 0x5b, 0x37, 0x7f, 0x66, 0xea, 0xde, }, // 1st
                  { 0x3d, 0xcf, 0xf8, 0xab, 0x1b, 0x58, 0x0d, 0x76, 0x8f, 0x9e, }, // 2nd
              },{ // 2nd file
                  { 0xd8, 0xd8, 0x6a, 0xd9, 0xaa, 0x93, 0x21, 0xc0, 0x6d, 0xd0, }, // rand
                  { 0x60, 0x91, 0x49, 0x1b, 0x0d, 0xd2, 0xba, 0x04, 0x15, 0x94, }, // 1st
                  { 0xd8, 0x0b, 0x6c, 0xe7, 0x77, 0x1c, 0x21, 0x1f, 0x90, 0x45, }, // 2nd
              }}}}},
    { 0, 0, 0, 0,
        { 13715, 1570652412, 1570665839, {{ 0x36718a59, 0x8f33c8ee, 0xdea1bb9d }},
            {{{ // 1st file
                  { 0x23, 0xa5, 0x24, 0x39, 0xab, 0xd9, 0xa6, 0xbe, 0x51, 0xf2, }, // rand
                  { 0xd2, 0x71, 0xbf, 0x46, 0x32, 0x27, 0xbc, 0x0e, 0xc5, 0x8b, }, // 1st
                  { 0x23, 0xda, 0x4e, 0x43, 0x1e, 0x75, 0xfd, 0x68, 0xde, 0x60, }, // 2nd
              },{ // 2nd file
                  { 0x44, 0xb7, 0x21, 0x15, 0x4a, 0x62, 0x1b, 0x45, 0x02, 0x19, }, // rand
                  { 0xb5, 0xeb, 0xdd, 0x66, 0x29, 0x29, 0x26, 0xfa, 0xfd, 0x5f, }, // 1st
                  { 0x44, 0x2e, 0x1a, 0x0c, 0x2a, 0x03, 0x6c, 0xbf, 0xb9, 0x3a, }, // 2nd
              }}}}},
    { 0, 0, 0, 0,
        { 13974, 1570652566, 1570666240, {{ 0x1fbf04f9, 0x755b317c, 0x2a7b0b67 }},
            {{{ // 1st file
                  { 0xb6, 0xdf, 0x87, 0x85, 0x26, 0x3e, 0xa9, 0x64, 0xd3, 0xa3, }, // rand
                  { 0x4e, 0x1f, 0xdf, 0xe9, 0xb7, 0x33, 0x14, 0x56, 0x57, 0x9f, }, // 1st
                  { 0xb6, 0x36, 0x31, 0xd6, 0x4a, 0xec, 0xaa, 0x13, 0xb9, 0xf6, }, // 2nd
              },{ // 2nd file
                  { 0x18, 0x7f, 0x7d, 0x30, 0xbb, 0x10, 0xd2, 0x11, 0x2b, 0x28, }, // rand
                  { 0xe0, 0xa1, 0x0f, 0x7b, 0x75, 0x98, 0xe5, 0x47, 0xb7, 0xc7, }, // 1st
                  { 0x18, 0xa9, 0xa0, 0xeb, 0x0d, 0x5a, 0x05, 0xe1, 0xff, 0x09, }, // 2nd
              }}}}},
    { 0, 0, 0, 0,
        { 14164, 1570652674, 1570665814, {{ 0x76cf6e60, 0x55abd9be, 0x02f6bd0a }},
            {{{ // 1st file
                  { 0x0f, 0x7d, 0xf2, 0x99, 0x0c, 0xdc, 0x36, 0x7f, 0xef, 0xcd, }, // rand
                  { 0x8e, 0x54, 0xb2, 0x44, 0x90, 0xfd, 0x59, 0x4a, 0x9a, 0x44, }, // 1st
                  { 0x0f, 0xf2, 0x80, 0x54, 0x49, 0x0b, 0x96, 0x11, 0x3c, 0x38, }, // 2nd
              },{ // 2nd file
                  { 0x41, 0xc4, 0xbb, 0x25, 0x9b, 0x24, 0x65, 0x2d, 0x90, 0x96, }, // rand
                  { 0xc0, 0xa4, 0xeb, 0xfa, 0x14, 0x58, 0xae, 0xf8, 0xde, 0x86, }, // 1st
                  { 0x41, 0x60, 0x0e, 0xda, 0x6a, 0xeb, 0xc4, 0xab, 0x05, 0x44, }, // 2nd
              }}}
        }
    }
}};

START_TEST(test_always_pass) {
    ck_assert(true);
}
END_TEST

START_TEST(test_stage1_operators) {
    const stage1_guess_t guess = {0x00ff, 0xaa, 0xbb, 0xcc, {{{0,0}, {0,0}}}};
    const stage1_guess_t guess_plus_one = {0x0100, 0xaa, 0xbb, 0xcc,
        {{{0,0}, {0,0}}}};
    auto other_guess(guess);

    ck_assert_msg(!(guess == guess_plus_one),
            "Expect !(guess == guess_plus_one)\n"
            "    guess: %s\n  guess+1: %s\n",
            guess.str().c_str(), guess_plus_one.str().c_str());
    ck_assert_msg(guess != guess_plus_one,
            "Expect guess != guess_plus_one\n"
            "    guess: %s\n  guess+1: %s\n",
            guess.str().c_str(), guess_plus_one.str().c_str());
    ck_assert(other_guess == guess);

    // There are sixteen 
    for (int i = 0; i < 15; ++i, ++other_guess) {
        if (0 < i) {
            ck_assert_msg(other_guess != guess && other_guess != guess_plus_one,
                "Expected three different guesses, got:\n"
                " guess_plus_one: %s\n"
                "    other_guess: %s\n"
                "          guess: %s\n",
                guess_plus_one.str().c_str(),
                other_guess.str().c_str(), guess.str().c_str());
        }
        ck_assert_msg(guess <= other_guess && other_guess < guess_plus_one,
                "Expected ordered guesses, got:\n"
                " guess_plus_one: %s\n"
                "    other_guess: %s\n"
                "          guess: %s\n",
                guess_plus_one.str().c_str(),
                other_guess.str().c_str(), guess.str().c_str());
    }

    ++other_guess;
    ck_assert(other_guess == guess_plus_one);


    ck_assert(other_guess > guess);
    ck_assert(guess < other_guess && guess < guess_plus_one);
}
END_TEST

START_TEST(test_stage1_ctor) {
    const stage1_guess_t s1_guess = {0x1122, 0x33, 0x44, 0x55, {{{1,0}, {0,1}}}};
    ck_assert(s1_guess.chunk1 == 0x1122);
    ck_assert(s1_guess.chunk2 == 0x33);
    ck_assert(s1_guess.chunk3 == 0x44);
    ck_assert(s1_guess.chunk4 == 0x55);
    ck_assert(s1_guess.carry_bits[0][0] == true);
    ck_assert(s1_guess.carry_bits[0][1] == false);
    ck_assert(s1_guess.carry_bits[1][0] == false);
    ck_assert(s1_guess.carry_bits[1][1] == true);
}
END_TEST

START_TEST(test_stage2_operators) {
    const stage1_guess_t s1_guess = {0x00ff, 0xaa, 0xbb, 0xcc, {{{0,0}, {0,0}}}};
    const stage2_guess_t guess = {s1_guess, 0x01, 0x11, 0x22, {{{0,0}, {0,0}}}};
    const stage2_guess_t guess_plus_one = {s1_guess, 0x02, 0x11, 0x22, {{{0,0}, {0,0}}}};
    auto other_guess(guess);

    ck_assert_msg(!(guess == guess_plus_one),
            "Expect !(guess == guess_plus_one)\n"
            "    guess: %s\n  guess+1: %s\n",
            guess.str().c_str(), guess_plus_one.str().c_str());
    ck_assert_msg(guess != guess_plus_one,
            "Expect guess != guess_plus_one\n"
            "    guess: %s\n  guess+1: %s\n",
            guess.str().c_str(), guess_plus_one.str().c_str());
    ck_assert(other_guess == guess);

    // There are sixteen 
    for (int i = 0; i < 15; ++i, ++other_guess) {
        if (0 < i) {
            ck_assert_msg(other_guess != guess && other_guess != guess_plus_one,
                "Expected three different guesses, got:\n"
                " guess_plus_one: %s\n"
                "    other_guess: %s\n"
                "          guess: %s\n",
                guess_plus_one.str().c_str(),
                other_guess.str().c_str(), guess.str().c_str());
        }
        ck_assert_msg(guess <= other_guess && other_guess < guess_plus_one,
                "Expected ordered guesses, got:\n"
                " guess_plus_one: %s\n"
                "    other_guess: %s\n"
                "          guess: %s\n",
                guess_plus_one.str().c_str(),
                other_guess.str().c_str(), guess.str().c_str());
    }

    ++other_guess;
    ck_assert(other_guess == guess_plus_one);


    ck_assert(other_guess > guess);
    ck_assert(guess < other_guess && guess < guess_plus_one);
}
END_TEST

START_TEST(test_stage2_ctor) {
    const stage2_guess_t zero_guess;
    ck_assert(zero_guess.chunk5 == 0x00);
    ck_assert(zero_guess.chunk6 == 0x00);
    ck_assert(zero_guess.chunk7 == 0x00);
    ck_assert(zero_guess.carry_bits[0][0] == false);
    ck_assert(zero_guess.carry_bits[0][1] == false);
    ck_assert(zero_guess.carry_bits[1][0] == false);
    ck_assert(zero_guess.carry_bits[1][1] == false);

    const stage2_guess_t guess = {0x11, 0x22, 0x33, {{{1,0}, {0,1}}}};
    ck_assert(guess.chunk5 == 0x11);
    ck_assert(guess.chunk6 == 0x22);
    ck_assert(guess.chunk7 == 0x33);
    ck_assert(guess.carry_bits[0][0] == true);
    ck_assert(guess.carry_bits[0][1] == false);
    ck_assert(guess.carry_bits[1][0] == false);
    ck_assert(guess.carry_bits[1][1] == true);
}
END_TEST

START_TEST(test_stage1_iterator) {

    const uint16_t END_CHUNK1 = 0x0005;
    const stage1_guess_t start = {0x0000, 0, 0, 0, {{{0,0}, {0,0}}}};
    const stage1_guess_t end   = {END_CHUNK1, 0, 0, 0, {{{0,0}, {0,0}}}};

    // NB(leaf): I'm really not sure this is right.
    const int num_between_expected = (END_CHUNK1 * 16) - 1;

    crack_t crack = {start, end, {0}, {0}, {}};

    bool start_was_included = false;
    int num_between = 0;
    int start_guesses = 0;
    bool end_was_included = false;

    fprintf(stderr, "stage1_iterator: start is %s\n",
            crack.stage1_start.hex().c_str());
    fprintf(stderr, "stage1_iterator:   end is %s\n",
            crack.stage1_end.hex().c_str());

    for (auto guess: stage1_range(crack)) {
        ck_assert(end >= guess);
        if (start == guess) {
            start_was_included = true;
        } else if (end == guess) {
            end_was_included = true;
        } else {
            ++num_between;
        }

        fprintf(stderr, "stage1_iterator: guess is %s\n", guess.hex().c_str());

        // Make sure we try all the carry bits.
        if (0 == guess.chunk1 && 0 == guess.chunk2 &&
                0 == guess.chunk3 && 0 == guess.chunk4) {
            start_guesses += 1;
        }
    }

    ck_assert_msg(16 == start_guesses,
            "Expected 4 guesses where chunks1-4 are zero, "
            "got %d instead.", start_guesses);

    ck_assert_msg(num_between_expected == num_between,
            "stage1_iterator: expected %d between start and end, got %d",
            num_between_expected, num_between);

    ck_assert_msg(start_was_included && !end_was_included && (0 < num_between),
            "start_was_included: %s\nend_was_included: %s\nnum_between: %d",
            start_was_included ? "yes" : "no",
            end_was_included ? "yes" : "no",
            num_between);
}
END_TEST

START_TEST(test_crypt) {

    for (auto crack_test: crypt_tests) {
        auto zip = crack_test.zip;

        uint8_t expected_s0s[2];

        int fileidx = 0;
        for (auto file: zip.files) {
            ck_assert_msg(file.random_bytes[0] == file.header_second[0],
                    "Invalid test data: random_bytes[0] is not decrypted in "
                    "header_second[0]!");
            expected_s0s[fileidx] = file.random_bytes[0] ^ file.header_first[0];
            ++fileidx;
        }

        ck_assert_msg(expected_s0s[0] == expected_s0s[1],
                "The s0's didn't match!");

        auto correct_guess = stage1_correct_guess(crack_test);
        auto stage1_start = stage1_correct_guess_start(correct_guess);
        auto stage1_end = stage1_correct_guess_end(correct_guess);

        ck_assert(correct_guess >= stage1_start);
        ck_assert_msg(correct_guess < stage1_end,
                "Correct: 0x%04x|%02x|%02x|%02x|%02x|%02x|%02x\n"
                "Stage End: 0x%04x|%02x|%02x|%02x|%02x|%02x|%02x\n",
                correct_guess.chunk1, correct_guess.chunk2, correct_guess.chunk3,
                correct_guess.chunk4, 
                stage1_end.chunk1, stage1_end.chunk2, stage1_end.chunk3,
                stage1_end.chunk4);

        ck_assert_msg(stage1_start != stage1_end,
                "Expect start != end, got: 0x%08lx == 0x%08lx",
                stage1_start, stage1_end);

        crack_test.stage1_start = stage1_start;
        crack_test.stage1_end = stage1_end;

        vector<stage1_guess_t> out;

        uint16_t expected_s0_arg = 0x100;
        expected_s0_arg |= (uint16_t)expected_s0s[0];
        ck_assert_msg((expected_s0_arg & 0xff00) == 0x100,
                "Expected s0 arg should be 0x100, was 0x%x",
                expected_s0_arg);

        ck_assert(stage1(&crack_test, out, correct_guess, expected_s0_arg));
        ck_assert_msg(out.size() > 0,
                "Expected at least one valid guess, got %d",
                out.size());

        int num_correct = 0;
        for (auto i: out) {
            fprintf(stderr, "stage1 guess: chunk1(0x%x) | chunk2(0x%x) | "
                    "chunk3(0x%x) | chunk4(0x%x) | carry(%x%x%x%x)\n",
                    i.chunk1, i.chunk2, i.chunk3, i.chunk4,
                    i.carry_bits[0][0], i.carry_bits[0][1],
                    i.carry_bits[1][0], i.carry_bits[1][1]);
            if (correct_guess == i) {
                ++num_correct;
            }
        }
        ck_assert_msg(num_correct == 1, "Correct guess not in list! num_correct=%d",
                num_correct);
    }
}
END_TEST

Suite* make_suite(const std::string name) {
    Suite* s;
    TCase* tc_core;
    s = suite_create(name.c_str());
    tc_core = tcase_create("core");

    /* Add every test case that you write below here. */
    tcase_add_test(tc_core, test_always_pass);
    tcase_add_test(tc_core, test_crypt);
    tcase_add_test(tc_core, test_stage1_iterator);
    tcase_add_test(tc_core, test_stage1_operators);
    tcase_add_test(tc_core, test_stage1_ctor);
    tcase_add_test(tc_core, test_stage2_operators);
    tcase_add_test(tc_core, test_stage2_ctor);

    suite_add_tcase(s, tc_core);
    return s;
}

int main(int argc, char* argv[]) {
    vector<string> inputs;
    InitBreakZip(argc, argv);

    int failed = 0;
    Suite* s = nullptr;
    SRunner* sr = nullptr;
    s = make_suite("pyr8::TEMPLATE");
    sr = srunner_create(s);
    srunner_run_all(sr, CK_VERBOSE);
    failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    auto return_val = (0 == failed ? EXIT_SUCCESS : EXIT_FAILURE);
    ShutdownBreakZip();
    return return_val;
}
