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

#include <stdio.h>
#include <cassert>
#include <cuda_runtime.h>
#include <sys/utsname.h>

// Utilities and timing functions
#include <helper_functions.h>    // includes cuda.h and cuda_runtime_api.h

// CUDA helper functions
#include <helper_cuda.h>         // helper functions for CUDA error check

const char *sampleName = "simpleAssert";

__device__ __managed__ int ret[1000];
__global__ void testKernel(int a, int b) {
    ret[threadIdx.x] = a + b + threadIdx.x;
}

START_TEST(test_always_pass) {
    findCudaDevice(0, nullptr);
    int A = 10, B = 100;
    testKernel<<<1, 1000>>>(A, B);
    cudaDeviceSynchronize();

    for (int i = 0; i < 1000; i++) {
        printf("%d: A+B = %d\n", i, ret[i]);
        ck_assert(ret[i] == (A + B + i));
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
