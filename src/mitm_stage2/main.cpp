#include <stdio.h>
#include <stdlib.h>

#include "breakzip.h"
#include "breakzip_config.h"
#include "mitm_stage1/crc32.h"
#include "mitm_stage1/mitm_stage1.h"
#include "mitm_stage2.h"

DEFINE_bool(runtests, false, "Run the test cases instead of attack.");
DEFINE_int32(shard, 0, "The shard to run on.");
DEFINE_string(outfile, "stage2.out", "The output file prefix to use.");
DEFINE_int32(srand_seed, 0x57700d32,
             "The srand seed that the file was created with.");

namespace mitm_stage2 {

/**
 * TODO(stay): Put your functions here.
 */

const char* usage_message = R"usage(
    Usage: mitm_stage2 <FILE> <OUT>
    Runs the stage2 attack using the zip file data in FILE, the shard specified
    by -shard, and writes output to the filename specified by -outfile with the
    shard number appended.
    )usage";

};  // namespace mitm_stage2

int main(int argc, char* argv[]) {
    using namespace mitm_stage2;
    using namespace breakzip;
    using namespace google;
    using namespace std;

    int my_argc = argc;

    SetVersionString(version_string());
    SetUsageMessage(usage_message);
    auto non_flag = ParseCommandLineFlags(&my_argc, &argv, false);

    if (non_flag >= argc) {
        ShowUsageWithFlags(argv[0]);
        exit(-1);
    }

    const char* input_filename = argv[non_flag];

    if (FLAGS_runtests) {
        /**
         * TODO(stay): Put test implementation here.
         */
        printf("Not implemented yet.\n");
        abort();
    } else {
        /**
         * TODO(leaf): Put real implementation here.
         */
        printf("Not implemented yet.\n");
        abort();
    }

    // TODO(stay): Close open files.
    return 0;
}
