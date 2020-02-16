#include <stdio.h>
#include <stdlib.h>

#include "stage3.h"

DECLARE_string(target);
DECLARE_bool(runtests);
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
using namespace stage3;
using namespace std;
using namespace breakzip;
using namespace google;

const char *usage_message = R"usage(
    Usage: mitm_stage2 <FILE> <OUT>
    Runs the stage2 attack using the stage1 data in FILE, the shard specified
    by -shard, and writes output to the filename specified by -outfile with the
    shard number appended.

    If you pass the -runtests argument, then the tests will fail unless the
    correct guess is contained within the shard you have provided via -target.
    Stage1 prints the name of the shard containing the correct guess.
    )usage";

int main(int argc, char *argv[]) {
    int my_argc = argc;

    SetVersionString(version_string());
    SetUsageMessage(usage_message);
    auto non_flag = ParseCommandLineFlags(&my_argc, &argv, false);

    // We build the preimages once for all candidates.
    vector<vector<uint16_t>> preimages(0x100);
    build_preimages(preimages);

    stage2_candidate *stage2_candidates = nullptr;
    uint32_t stage2_candidate_count = 0;
    read_stage2_candidates(&stage2_candidates, &stage2_candidate_count);

    if (0 == stage2_candidate_count) {
        fprintf(stderr, "FATAL: Read no candidates from input file.\n");
        exit(-1);
    }

    if (nullptr == stage2_candidates) {
        fprintf(stderr, "FATAL: Stage2 candidates array was null.\n");
        exit(-1);
    }

    fprintf(stdout, "Read %d candidates from stage2.\n",
            stage2_candidate_count);

    archive_info archive;
    size_t idx = 0;
    correct_guess guess[2] = {correct(mitm::test[0]), correct(mitm::test[1])};
    correct_guess *c = nullptr;

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

    if (FLAGS_runtests) {
        c = &(guess[0]);
        archive = mitm::test[0];
    }

    if ((archive.file[0].x[0] != archive.file[0].h[0]) ||
        (archive.file[1].x[0] != archive.file[1].h[0])) {
        fprintf(stderr, "Given seed does not generate the initial bytes!");
        exit(-1);
    }

    printf(
        "Starting stage3 for target archive `%s` and input shard `%s`...\n",
        FLAGS_runtests ? "Test archive 0" : (const char *)FLAGS_target.c_str(),
        FLAGS_input_shard.c_str());

    keys result = {0, 0, 0};
    for (int i = 0; i < stage2_candidate_count; ++i) {
        gpu_stage3(archive, stage2_candidates[i], &result, c);
        if (result.crck00 != 0 || result.k10 != 0 || result.k20 != 0) {
            fprintf(stderr, "Found keys! crck00: %08x, k10: %08x, k20: %08x\n",
                    result.crck00, result.k10, result.k20);
        }
    }

    return 0;
}
