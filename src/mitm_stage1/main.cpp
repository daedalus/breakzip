#include <stdio.h>
#include <stdlib.h>

#include "crc32.h"
#include "mitm_stage1.h"
#include "breakzip.h"
#include "breakzip_config.h"

DEFINE_bool(runtests, false, "Run the test cases instead of attack.");
DEFINE_string(target, "target.zip", "Name of the target ZIP file.");
DEFINE_int32(srand_seed, 0x57700d32, "The srand seed that the file was created with.");

namespace mitm_stage1 {
    archive_info test[2] = {
        // test 0
        {
            // file
            {
                // file 0
                {
                    // x
                    {0x0d, 0x33, 0xb6, 0x64, 0x5e, 0x66, 0xc0, 0x02, 0xfe, 0x13},
                    // h
                    {0x0d, 0xde, 0x72, 0xc2, 0x22, 0x5e, 0xaf, 0x75, 0x8a, 0x6c},
                    // y
                    {0x17, 0x44, 0xd0, 0xe8, 0x08, 0x48, 0x09, 0x89, 0x1d, 0x5f}
                },
                // file 1
                {
                    // x
                    {0x4e, 0x8a, 0x3c, 0x9a, 0x72, 0x23, 0x41, 0xbe, 0xab, 0xb0},
                    // h
                    {0x4e, 0xc3, 0x69, 0xf4, 0x97, 0x6e, 0x5a, 0x66, 0x77, 0xcb},
                    // y
                    {0x54, 0x34, 0xf2, 0x0b, 0x6b, 0x08, 0x3d, 0x17, 0xb2, 0xbf}
                }
            },
            // key
            {0xe4858bae, 0xa8254576, 0x3743e7bb}
        },
        // test 1
        {
            // file
            {
                // file 0
                {
                    // x
                    {0x20, 0x95, 0x07, 0xa5, 0xb9, 0x4c, 0x99, 0xcc, 0xe7, 0x4a},
                    // h
                    {0x20, 0x7e, 0xbd, 0xf1, 0xb2, 0x4e, 0xd9, 0xea, 0xa9, 0xc6},
                    // y
                    {0x12, 0x27, 0x02, 0xf6, 0x62, 0xe7, 0x23, 0xfc, 0x18, 0xb5}
                },
                {
                    // x
                    {0x3d, 0xff, 0x6c, 0xe0, 0x91, 0xbf, 0xc2, 0x2b, 0xca, 0x90},
                    // h
                    {0x3d, 0x4c, 0xed, 0x9f, 0x49, 0xf9, 0x78, 0x53, 0xee, 0x14},
                    // y
                    {0x0f, 0xe4, 0xa7, 0x4a, 0x4d, 0x82, 0x82, 0x1e, 0xc9, 0x57}
                }
            },
            // key
            {0x1e096225, 0xcb831619, 0x296e7f2b}
        }
    };

    void write_word(FILE *f, uint32_t w) {
        fputc(w & 0xff, f);
        fputc((w >> 8) & 0xff, f);
        fputc((w >> 16) & 0xff, f);
        fputc((w >> 24) & 0xff, f);
    }

    void write_candidate(FILE *f, stage1_candidate &c) {
        uint8_t size = (uint8_t)(c.maybek20.size());
        fputc(size, f);
        for (uint16_t i = 0; i < size; ++i) {
            write_word(f, c.maybek20[i]);
        }
        fputc(c.chunk2, f);
        fputc(c.chunk3, f);
        fputc(c.cb1, f);
    }

    void write_candidates(FILE *f, vector<stage1_candidate>& candidates) {
        uint32_t size = (uint32_t)candidates.size();
        write_word(f, size);
        for (uint32_t i = 0; i < size; ++i) {
            write_candidate(f, candidates[i]);
        }
    }

    const char *usage_message = R"usage(
    Usage: mitm_stage1 <FILE> 
    Runs the stage1 meet-in-the-middle attack on FILE.
    )usage";

}; // namespace

int main(int argc, char* argv[]) {
    using namespace mitm_stage1;
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

    const char* output_filename = argv[non_flag];
    FILE *output_file = fopen(output_filename, "wb");
    if (nullptr == output_file) {
        perror("Can't open output file");
        exit(1);
    }

    if (FLAGS_runtests) {
        correct_guess guess[2] = { correct(test[0]), correct(test[1]) };
        vector<vector<stage1a>> table(0x01000000);
        vector<stage1_candidate> candidates(0);
        vector<vector<uint16_t>> preimages(0x100);

        build_preimages(preimages);
        mitm_stage1a(test[0], table, &(guess[0]));
        mitm_stage1b(test[0], table, candidates, output_file, preimages, &(guess[0]));
        write_candidates(output_file, candidates);
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
        mitm_stage1b(archive, table, candidates, output_file, preimages);
        write_candidates(output_file, candidates);
    }

    fclose(output_file);
    return 0;
}
