#include <stdio.h>
#include <stdlib.h>

#include "breakzip.h"
#include "breakzip_config.h"
#include "crc32.h"
#include "mitm_stage1.h"

DECLARE_bool(runtests);
DECLARE_bool(only_emit_correct);
DECLARE_string(target);
DECLARE_int32(srand_seed);

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

    if (FLAGS_only_emit_correct) {
        FLAGS_runtests = true;
    }

    if (FLAGS_runtests) {
        correct_guess guess[2] = {correct(mitm::test[0]),
                                  correct(mitm::test[1])};
        vector<vector<stage1a>> table(0x01000000);
        vector<stage1_candidate> candidates(0);
        size_t correct_idx = 0;

        mitm_stage1a(test[0], table, &(guess[0]));
        mitm_stage1b(test[0], table, candidates, &(guess[0]), &correct_idx);

        if (correct_candidate(guess[0], candidates[correct_idx])) {
            printf(
                "The correct candidate appears in the candidates list at index "
                "%ld.\n",
                correct_idx);
        } else {
            printf("Unable to find correct guess in candidates vector!\n");
            abort();
        }

        printf("\nWriting candidates to output shards...\n");
        write_stage1_candidates(candidates, correct_idx);

    } else {
        archive_info archive;

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

        for (int f = 0; f < 2; ++f) {
            fprintf(stderr, "file %d\nx = ", f);
            for (int i = 0; i < 10; ++i) {
                fprintf(stderr, "%02x, ", archive.file[f].x[i]);
            }
            fprintf(stderr, "\nh = ");
            for (int i = 0; i < 10; ++i) {
                fprintf(stderr, "%02x, ", archive.file[f].h[i]);
            }
            fprintf(stderr, "\n");
        }

        if ((archive.file[0].x[0] != archive.file[0].h[0]) ||
            (archive.file[1].x[0] != archive.file[1].h[0])) {
            fprintf(stderr,
                    "Given seed does not generate the initial bytes!\n");
            exit(-1);
        }

        vector<vector<stage1a>> table(0x01000000);
        vector<stage1_candidate> candidates(0);

        mitm_stage1a(archive, table);
        mitm_stage1b(archive, table, candidates);
        write_stage1_candidates(candidates);
    }

    return 0;
}
