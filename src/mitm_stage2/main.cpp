#include <stdio.h>
#include <stdlib.h>

#include "breakzip.h"
#include "breakzip_config.h"
#include "crc32.h"
#include "mitm_common.h"
#include "mitm_stage1/mitm_stage1.h"
#include "mitm_stage2.h"

DECLARE_string(target);
DECLARE_bool(runtests);
DECLARE_bool(only_emit_correct);
DEFINE_string(input_shard, "target.out.0",
              "The filename of the stage1 shard to run on.");
DECLARE_string(output);
DECLARE_int32(srand_seed);
DEFINE_int32(stop_after, -1,
             "If set to a positive value, the program "
             "will stop after processing <stop_after> stage1 candidates.");

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

    If you pass the -runtests argument, then the tests will fail unless the
    correct guess is contained within the shard you have provided via -target.
    Stage1 prints the name of the shard containing the correct guess.
    )usage";

int main(int argc, char* argv[]) {
    int my_argc = argc;

    SetVersionString(version_string());
    SetUsageMessage(usage_message);
    auto non_flag = ParseCommandLineFlags(&my_argc, &argv, false);

    if (FLAGS_only_emit_correct) {
        FLAGS_runtests = true;
    }

    const char* input_filename = argv[non_flag];

    // Read all the stage1 candidates into memory at once.
    vector<stage1_candidate> candidates;

    // There are about 84,000 stage2_candidates per stage1_candidate.
    const size_t S2CANDIDATE_ARRAYSZ = 125000;
    stage2_candidate* stage2_candidates = (stage2_candidate*)::calloc(
        S2CANDIDATE_ARRAYSZ, sizeof(stage2_candidate));

    if (nullptr == stage2_candidates) {
        perror("Allocation failed");
        exit(-1);
    }

    auto input_file = fopen(FLAGS_input_shard.c_str(), "r");
    if (nullptr == input_file) {
        perror("Can't open input file");
        exit(-1);
    }

    read_stage1_candidates(input_file, candidates);

    if (0 == candidates.size()) {
        fprintf(stderr, "FATAL: Read no stage1 candidates from input file.\n");
        exit(-1);
    }

    fprintf(stdout, "Read %ld candidates from stage1.\n", candidates.size());

    if (FLAGS_runtests) {
        correct_guess guess[2] = {correct(mitm::test[0]),
                                  correct(mitm::test[1])};

        size_t idx = 0;
        size_t stage2_candidate_total = 0;
        printf("Starting stage2... %ld candidates\n", candidates.size());
        for (auto candidate : candidates) {
            if (idx++ < 9234) { continue; }
            // Clear the output array.
            ::memset(stage2_candidates, 0,
                     S2CANDIDATE_ARRAYSZ * sizeof(stage2_candidate));
            size_t stage2_candidate_count = 0;

            printf("On stage1 candidate %ld...\n", idx);

            vector<vector<stage2a>> table(0x1000000);
            mitm_stage2a(test[0], candidate, table, guess);
            mitm_stage2b(test[0], candidate, table, stage2_candidates,
                         S2CANDIDATE_ARRAYSZ, stage2_candidate_count, guess);

            stage2_candidate_total += stage2_candidate_count;
            printf("stage1[%lu] => %lu candidates, %lu total.\n", idx,
                   stage2_candidate_count, stage2_candidate_total);
            write_stage2_candidates(stage2_candidates, stage2_candidate_count,
                                    idx);

            if (FLAGS_stop_after <= idx) {
                fprintf(stderr, "Stopping after %d candidates. Goodbye.\n",
                        (int)idx);
                break;
            }
        }

    } else {
        archive_info archive;
        size_t idx = 0;
        size_t stage2_candidate_total = 0;

        // Generate the x array from the seed.
        srand(FLAGS_srand_seed);
        for (int j = 0; j < 2; ++j) {
            for (int i = 0; i < 10; ++i) {
                archive.file[j].x[i] = rand() >> 7;
            }
        }

        // Acquire the h array from the file.
        auto zfile = new ZipFile(FLAGS_target);
        if (0 != zfile->init()) {
            perror("Couldn't initialize target ZIP file");
            exit(-1);
        }

        auto lfhs = zfile->local_file_headers();
        // NB(leaf): This is a bug if the target file has more than two files
        // because the MITM types don't support more than two.
        for (int i = 0; i < lfhs.size(); ++i) {
            auto crypt_header = lfhs[i]->crypt_header();
            for (int j = 0; j < 10; ++j) {
                archive.file[i].h[j] = crypt_header[j];
            }
        }

        if ((archive.file[0].x[0] != archive.file[0].h[0]) ||
            (archive.file[1].x[0] != archive.file[1].h[0])) {
            fprintf(stderr, "Given seed does not generate the initial bytes!");
            exit(-1);
        }

        printf(
            "Starting stage2 for target archive `%s` and input shard `%s`...\n",
            FLAGS_target.c_str(), FLAGS_input_shard.c_str());
        for (auto candidate : candidates) {
            // Clear the output array.
            ::memset(stage2_candidates, 0,
                     S2CANDIDATE_ARRAYSZ * sizeof(stage2_candidate));
            size_t stage2_candidate_count = 0;

            if (++idx % 1000) {
                printf("On stage1 candidate %ld...\n", idx);
            }

            vector<vector<stage2a>> table(0x1000000);
            mitm_stage2a(archive, candidate, table);
            mitm_stage2b(archive, candidate, table, stage2_candidates,
                         S2CANDIDATE_ARRAYSZ, stage2_candidate_count);

            stage2_candidate_total += stage2_candidate_count;
            printf("stage1[%lu] => %lu candidates, %lu total.\n", idx,
                   stage2_candidate_count, stage2_candidate_total);
            for (int i = 0; i < stage2_candidate_count; ++i) {
                // sanity check
                if (0 == stage2_candidates[i].k20_count) {
                    fprintf(stderr, "Assert failed: candidate %d has %d maybek20's\n",
                            i, stage2_candidates[i].k20_count);
                    abort();
                }
            }
            write_stage2_candidates(stage2_candidates, stage2_candidate_count,
                                    idx);

            if (FLAGS_stop_after <= idx) {
                fprintf(stderr, "Stopping after %d candidates. Goodbye.\n",
                        (int)idx);
                break;
            }
        }
    }

    // TODO(stay): Close open files.
    return 0;
}
