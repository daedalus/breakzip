#include <stdio.h>
#include <stdlib.h>

#include "breakzip.h"
#include "breakzip_config.h"
#include "crc32.h"
#include "mitm_stage1.h"

DEFINE_bool(runtests, false, "Run the test cases instead of attack.");
DEFINE_string(target, "target.zip", "Name of the target ZIP file.");
DEFINE_int32(srand_seed, 0x57700d32,
             "The srand seed that the file was created with.");

using namespace mitm;
using namespace mitm_stage1;
using namespace breakzip;
using namespace google;
using namespace std;

const char *usage_message = R"usage(
    Usage: mitm_stage1 [-target <ZIPFILE>] [-output <OUTFILE>]
    Runs the stage1 meet-in-the-middle attack on ZIPFILE, writing the data to
    OUTFILE.
    )usage";

int main(int argc, char *argv[]) {

    int my_argc = argc;

    SetVersionString(version_string());
    SetUsageMessage(usage_message);
    auto non_flag = ParseCommandLineFlags(&my_argc, &argv, false);

    if (FLAGS_runtests) {
        correct_guess guess[2] = {
            correct(mitm::test[0]), correct(mitm::test[1])
        };
        vector<vector<stage1a>> table(0x01000000);
        vector<stage1_candidate> candidates(0);
        vector<vector<uint16_t>> preimages(0x100);
        size_t correct_idx = 0;

        build_preimages(preimages);
        printf("Generated %ld preimages.\n", preimages.size());
        mitm_stage1a(test[0], table, &(guess[0]));
        mitm_stage1b(test[0], table, candidates, preimages, &(guess[0]), &correct_idx);

        if (correct_candidate(guess[0], candidates[correct_idx])) {
            printf("The correct candidate appears in the candidates list at index "
                   "%ld.\n", correct_idx);
        } else {
            printf("Unable to find correct guess in candidates vector!\n");
            abort();
        }

        printf("\nWriting candidates to output shards...\n");
        write_candidates(candidates, correct_idx);

    } else {
        archive_info archive;

        // Generate the x array from the seed.
        srand(FLAGS_srand_seed);
        for (int j = 0; j < 2; ++j) {
            for (int i = 0; i < 10; ++i) {
                archive.file[j].x[i] = rand();
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

        vector<vector<stage1a>> table(0x01000000);
        vector<stage1_candidate> candidates(0);
        vector<vector<uint16_t>> preimages(0x100);

        build_preimages(preimages);
        mitm_stage1a(archive, table);
        mitm_stage1b(archive, table, candidates, preimages);
        write_candidates(candidates);

    }

    return 0;
}
