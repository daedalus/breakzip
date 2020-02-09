/* Copyright (c) 2016, Pyrofex Corporation.
 * All right reserved.
 * Author: Nash E. Foster <leaf@pyrofex.com>
 */
#include <iostream>
#include <limits>
#include <stdio.h>
#include <stdlib.h>
#include <string>

#include <check.h>

#include <gflags/gflags.h>

#include "../breakzip.h"

using namespace breakzip;
using namespace mitm;
using namespace mitm_stage1;
using namespace std;

START_TEST(test_always_pass) {
    ck_assert(true);
}
END_TEST


START_TEST(test_write_word) {
    auto tmp = tmpfile();
    for (uint32_t word = 0; word < 0x100000; ++word) {
        write_word(tmp, word);
    }

    fseek(tmp, 0, SEEK_SET);

    for (uint32_t word = 0; word < 0x100000; ++word) {
        uint32_t tmpword = 0;
        read_word(tmp, tmpword);
        ck_assert_msg(tmpword == word,
                      "read_word failed: expected %d, got %d\n",
                      word, tmpword);
    }

    fclose(tmp);
}
END_TEST

START_TEST(test_write_3bytes) {
    auto tmp = tmpfile();
    for (uint32_t word = 0; word < 0x1000000; ++word) {
        write_3bytes(tmp, word);
    }

    fseek(tmp, 0, SEEK_SET);

    for (uint32_t word = 0; word < 0x1000000; ++word) {
        uint32_t tmpword = 0;
        read_3bytes(tmp, tmpword);
        ck_assert_msg(tmpword == word,
                      "read_3bytes failed: expected %d, got %d\n",
                      word, tmpword);
    }

    fclose(tmp);
}
END_TEST

START_TEST(test_stage1_candidate) {

    stage1_candidate cand;
    cand.chunk2 = 0xAA;
    cand.chunk3 = 0xBB;
    cand.cb1 = 0xCC;
    cand.m1 = 0x00112233;

    auto tmp = tmpfile();
    for (int k20s = 1; k20s < stage1_candidate::MAX_K20S; ++k20s) {
        fseek(tmp, 0, SEEK_SET);
        cand.k20_count = k20s;
        for (int i = 0; i < k20s; ++i) {
            cand.maybek20[i] = i;
        }

        write_stage1_candidate(tmp, cand);
        fseek(tmp, 0, SEEK_SET);

        stage1_candidate rcand;
        read_stage1_candidate(tmp, rcand);

        ck_assert(cand.chunk2 == rcand.chunk2);
        ck_assert(cand.chunk3 == rcand.chunk3);
        ck_assert(cand.cb1 == rcand.cb1);
        ck_assert(cand.m1 == rcand.m1);
        ck_assert_msg(rcand.k20_count != 0);
        ck_assert_msg(cand.k20_count == rcand.k20_count,
                      "Expected k20 count of %d, got %d instead.\n",
                      cand.k20_count, rcand.k20_count);

        for (int j = 0; j < k20s; ++j) {
            ck_assert(cand.maybek20[j] == j);
            ck_assert(cand.maybek20[j] == rcand.maybek20[j]);
        }
    }

    fclose(tmp);
}
END_TEST

START_TEST(test_stage1_candidates) {
    auto tmp = tmpfile();
    vector<stage1_candidate> candidates;

    stage1_candidate base_cand;
    base_cand.chunk2 = 0xAA;
    base_cand.chunk3 = 0xBB;
    base_cand.cb1 = 0xCC;
    base_cand.m1 = 0x00112233;
    
    for (int k20s = 1; k20s < stage1_candidate::MAX_K20S; ++k20s) {
        stage1_candidate cand = base_cand;
        for (int i = 0; i < k20s; ++i) {
            cand.maybek20[i] = i;
        }
        cand.k20_count = k20s;

        candidates.push_back(cand);
    }

    write_stage1_candidate_file(tmp, candidates, 0, candidates.size());
    fseek(tmp, 0, SEEK_SET);

    vector<stage1_candidate> read_candidates;
    read_stage1_candidates(tmp, read_candidates);
    ck_assert(candidates.size() == read_candidates.size());
    for (int i = 0; i < candidates.size(); ++i) {
        ck_assert(candidates[i] == read_candidates[i]);
    }

    fclose(tmp);
}
END_TEST

Suite* make_suite(const std::string name) {
    Suite* s;
    TCase* tc_core;
    s = suite_create(name.c_str());
    tc_core = tcase_create("core");

    /* Add every test case that you write below here. */
    tcase_add_test(tc_core, test_always_pass);
    tcase_add_test(tc_core, test_write_word);
    tcase_add_test(tc_core, test_stage1_candidate);
    tcase_add_test(tc_core, test_stage1_candidates);

    suite_add_tcase(s, tc_core);
    return s;
}

int main(int argc, char* argv[]) {
    vector<string> inputs;
    
    int failed = 0;
    Suite* s = nullptr;
    SRunner* sr = nullptr;
    s = make_suite("pyr8::TEMPLATE");
    sr = srunner_create(s);
    srunner_run_all(sr, CK_VERBOSE);
    failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    auto return_val = (0 == failed ? EXIT_SUCCESS : EXIT_FAILURE);
    return return_val;
}
