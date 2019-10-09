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
crack_t crypt_tests[5] = {
    {
        0, 0, // start, end
        {
            13426, 1570546266, 1570543144, // pid, time, seed
            { 0xe4858bae, 0xa8254576, 0x3743e7bb }, // keys
            {
                { // 1st file
                    { 0x0d, 0x33, 0xb6, 0x64, 0x5e, 0x66, 0xc0, 0x02, 0xfe, 0x13 }, // rand
                    { 0x17, 0x44, 0xd0, 0xe8, 0x08, 0x48, 0x09, 0x89, 0x1d, 0x5f }, // 1st
                    { 0x0d, 0xde, 0x72, 0xc2, 0x22, 0x5e, 0xaf, 0x75, 0x8a, 0x6c }, // 2nd
                },{ // 2nd file
                    { 0x4e, 0x8a, 0x3c, 0x9a, 0x72, 0x23, 0x41, 0xbe, 0xab, 0xb0 }, // rand
                    { 0x54, 0x34, 0xf2, 0x0b, 0x6b, 0x08, 0x3d, 0x17, 0xb2, 0xbf }, // 1st
                    { 0x4e, 0xc3, 0x69, 0xf4, 0x97, 0x6e, 0x5a, 0x66, 0x77, 0xcb }, // 2nd
                }
            }
        }
    },{
        0, 0, // start, end
        {
            13428, 1570546267, 1570543151, // pid, time, seed
            { 0x1e096225, 0xcb831619, 0x296e7f2b }, // keys
            { // files
                { // 1st file
                    { 0x20, 0x95, 0x07, 0xa5, 0xb9, 0x4c, 0x99, 0xcc, 0xe7, 0x4a }, // rand
                    { 0x12, 0x27, 0x02, 0xf6, 0x62, 0xe7, 0x23, 0xfc, 0x18, 0xb5 }, // 1st
                    { 0x20, 0x7e, 0xbd, 0xf1, 0xb2, 0x4e, 0xd9, 0xea, 0xa9, 0xc6 }, // 2nd
                },{ // 2nd file
                    { 0x3d, 0xff, 0x6c, 0xe0, 0x91, 0xbf, 0xc2, 0x2b, 0xca, 0x90 }, // rand
                    { 0x0f, 0xe4, 0xa7, 0x4a, 0x4d, 0x82, 0x82, 0x1e, 0xc9, 0x57 }, // 1st
                    { 0x3d, 0x4c, 0xed, 0x9f, 0x49, 0xf9, 0x78, 0x53, 0xee, 0x14 }, // 2nd
                }
            }
        }
    },{
        0, 0, // start, end
        { 13429, 1570546269, 1570543144, // pid, time, seed
            { 0x10d2ea17, 0x5b0bddd3, 0xd961ec6f }, // keys
            { // files
                { // 1st file
                    { 0x0d, 0x33, 0xb6, 0x64, 0x5e, 0x66, 0xc0, 0x02, 0xfe, 0x13 }, // rand
                    { 0xe6, 0x7b, 0xe8, 0x2f, 0x3f, 0x97, 0x6f, 0x26, 0x37, 0x08 }, // 1st
                    { 0x0d, 0xe0, 0xad, 0xc9, 0x9d, 0x97, 0x57, 0x7b, 0x1d, 0x94 }, // 2nd
                },{ // 2nd file
                    { 0x4e, 0x8a, 0x3c, 0x9a, 0x72, 0x23, 0x41, 0xbe, 0xab, 0xb0 }, // rand
                    { 0xa5, 0x74, 0x9c, 0x7d, 0x0d, 0xd4, 0xc2, 0x91, 0x55, 0xda }, // 1st
                    { 0x4e, 0x79, 0x47, 0x98, 0x38, 0x78, 0x26, 0x57, 0x49, 0x9a }, // 2nd
                }
            }
        }
    },{
        0, 0, // start, end
        {
            13430, 1570546271, 1570543145, // pid, time, seeed
            { 0x7d9315a2, 0xfa9f7fba, 0x15be19ef }, // keys
            { // files
                { // 1st file
                    { 0x56, 0x28, 0xf7, 0x7d, 0xf8, 0x4e, 0x9a, 0x32, 0x38, 0x8b }, // rand
                    { 0x25, 0x37, 0x5c, 0xe3, 0xf0, 0x2e, 0x3c, 0x25, 0x11, 0x55 }, // 1st
                    { 0x56, 0x01, 0x88, 0x79, 0x3f, 0x36, 0x44, 0xbb, 0xdf, 0x02 }, // 2nd
                },{ // 2nd file 
                    { 0x9a, 0x88, 0x62, 0x14, 0xa5, 0x6b, 0xf8, 0x2c, 0x58, 0x05 }, // rand
                    { 0xe9, 0xc5, 0xb5, 0x58, 0x15, 0xf3, 0x00, 0xad, 0xf8, 0x13 }, // 1st
                    { 0x9a, 0x6a, 0xed, 0xae, 0x4d, 0x27, 0x0a, 0x16, 0xe8, 0x45 }, // 2nd
                }
            }
        }
    },{
        0, 0, // start, end
        {
            13431, 1570546274, 1570543125, // pid, time, seed
            { 0x31dc100l, 0x64feafb1, 0x2f4333bb }, // keys
            { // files
                { // 1st file
                    { 0xc0, 0xa5, 0x7e, 0x9b, 0x5f, 0xb4, 0x19, 0x01, 0xe4, 0xc1 }, // rand
                    { 0x16, 0xeb, 0x03, 0x31, 0x30, 0x86, 0x47, 0x29, 0x05, 0xaf }, // 1st
                    { 0xc0, 0xaf, 0xbd, 0xa9, 0xcf, 0x4c, 0xbe, 0xf9, 0x71, 0x6c }, // 2nd
                },{ // 2nd file
                    { 0x03, 0xb1, 0xb4, 0x65, 0x91, 0xde, 0x77, 0x18, 0xfd, 0x6f }, // rand
                    { 0xd5, 0xa4, 0x97, 0x37, 0x1c, 0x69, 0x28, 0xfd, 0x8d, 0xda }, // 1st
                    { 0x03, 0xcb, 0xca, 0xf1, 0xba, 0x52, 0xff, 0x94, 0xd6, 0x26 }, // 2nd
                }
            }
        }
    }
};

START_TEST(test_always_pass) {
    ck_assert(true);
}
END_TEST

START_TEST(test_crypt) {

    for (auto crack_test: crypt_tests) {
        auto zip = crack_test.zip;

        for (auto file: zip.files) {
            ck_assert_msg(file.random_bytes[0] == file.header_second[0],
                    "Invalid test data: random_bytes[0] is not decrypted in "
                    "header_second[0]!");
        }

        // TODO(leaf): This should fail for now, make it pass once we have start/end
        // data for the archives under test.
        //ck_assert(crack_test.stage1_start != crack_test.stage1_end);
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
