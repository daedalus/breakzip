#include <stdio.h>
#include <stdlib.h>

#include "breakzip.h"
#include "breakzip_config.h"
#include "crc32.h"
#include "mitm_common.h"
#include "mitm_stage1/mitm_stage1.h"
#include "mitm_stage2.h"

DEFINE_bool(runtests, false, "Run the test cases instead of attack.");
DEFINE_string(target, "target.out.0", "The filename of the stage1 shard to run on.");
DEFINE_string(outfile, "stage2.out", "The output file prefix to use.");
DEFINE_int32(srand_seed, 0x57700d32,
             "The srand seed that the file was created with.");

using namespace mitm;
using namespace mitm_stage1;
using namespace mitm_stage2;
using namespace std;
using namespace breakzip;
using namespace google;

const char* usage_message = R"usage(
    Usage: mitm_stage2 <FILE> <OUT>
    Runs the stage2 attack using the stage1 data in FILE, the shard specified
    by -shard, and writes output to the filename specified by -outfile with the
    shard number appended.
    )usage";

int main(int argc, char* argv[]) {
    using namespace mitm_stage2;
    using namespace breakzip;
    using namespace google;
    using namespace std;

    int my_argc = argc;

    SetVersionString(version_string());
    SetUsageMessage(usage_message);
    auto non_flag = ParseCommandLineFlags(&my_argc, &argv, false);

    const char* input_filename = argv[non_flag];

    if (FLAGS_runtests) {
        correct_guess guess[2] = {
            correct(mitm::test[0]), correct(mitm::test[1])
        };

        vector<stage1_candidate> candidates;
        vector<vector<stage2a>> table(0x1000000);

        // TODO(leaf): find the correct guess in the input file.
        // candidates.push_back(guess[0]);

        for (auto candidate: candidates) {
            mitm_stage2a(test[0], candidate, table, guess);
        }

        if (1 != table.size()) {
            fprintf(stderr, "Error: correct guess did not end up "
                "in output table.\n");
            exit(-1);
        }

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
