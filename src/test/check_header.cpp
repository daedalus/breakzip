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

using namespace breakzip;
using namespace std;

START_TEST(test_always_pass) {
    ck_assert(true);
}
END_TEST

Suite* make_suite(const std::string name) {
    Suite* s;
    TCase* tc_core;
    s = suite_create(name.c_str());
    tc_core = tcase_create("core");

    /* Add every test case that you write below here. */
    tcase_add_test(tc_core, test_always_pass);

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
