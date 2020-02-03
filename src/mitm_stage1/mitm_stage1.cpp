#include <stdio.h>
#include <stdlib.h>

#include "breakzip.h"
#include "mitm_stage1.h"

DEFINE_string(output, "stage.out",
              "Output file basename. Shard files will be named"
              "BASENAME.X for shard number X.");
DEFINE_int32(shard_size, 10000, "Size of an output shard.");
DEFINE_string(target, "target.zip", "Name of the target ZIP file.");
DEFINE_int32(srand_seed, 0x57700d32,
             "The srand seed that the file was created with.");
DEFINE_bool(runtests, false, "Run the test cases instead of attack.");

using namespace std;
using namespace mitm;

namespace mitm_stage1 {

bool correct_candidate(const mitm::correct_guess &g,
                       const stage1_candidate &c) {
    bool result = false;
    uint32_t true_k20 = (g.chunk4 << 16) | g.chunk1;
    for (int i = 0; i < c.k20_count; ++i) {
        result = result || (c.maybek20[i] == true_k20);
    }
    result = result && (c.chunk2 == g.chunk2 && c.chunk3 == g.chunk3 &&
                        c.cb1 == (g.carries >> 12));
    return result;
}

void write_candidate(FILE *f, stage1_candidate &c) {
    const uint8_t size = c.k20_count;
    fputc(size, f);
    for (uint16_t i = 0; i < size; ++i) {
        write_3bytes(f, c.maybek20[i]);
    }
    fputc(c.chunk2, f);
    fputc(c.chunk3, f);
    fputc(c.cb1, f);
    write_word(f, c.m1);
}

void read_candidate(FILE *f, stage1_candidate &c) {
    const uint8_t size = (uint8_t)fgetc(f);
    c.k20_count = 0;
    for (uint8_t i = 0; i < size; ++i) {
        uint32_t maybek20 = 0;
        read_3bytes(f, maybek20);
        c.maybek20[i] = maybek20;
        ++(c.k20_count);
    }
    c.chunk2 = (uint8_t)fgetc(f);
    c.chunk3 = (uint8_t)fgetc(f);
    c.cb1 = (uint8_t)fgetc(f);
    read_word(f, c.m1);
}

void read_candidates(FILE *f, vector<stage1_candidate> &out) {
    uint32_t num_candidates = 0;
    read_word(f, num_candidates);

    printf("read_candidates: file should contain %d candidates\n",
           num_candidates);
    for (int i = 0; i < num_candidates; ++i) {
        stage1_candidate c;
        read_candidate(f, c);
        out.push_back(c);
    }
}

void write_candidates(vector<stage1_candidate> &candidates,
                      size_t correct_index) {
    size_t filename_len = FLAGS_output.length() + 16;
    char *output_filename = (char *)::calloc(filename_len, sizeof(char));

    auto num_shards = (candidates.size() / FLAGS_shard_size) + 1;
    auto candidates_remaining = candidates.size();
    size_t shard_start = 0;
    size_t shard_end = SIZE_MAX;

    printf(
        "There are %ld candidates.\n"
        "Shards are %d candidates long.\n"
        "%ld shards expected.\n",
        candidates.size(), FLAGS_shard_size, num_shards);

    unsigned long int shard_index = 0;
    while (0 < candidates_remaining) {
        snprintf(output_filename, filename_len, "%s.%ld", FLAGS_output.c_str(),
                 shard_index);
        FILE *output_file = fopen(output_filename, "wb");
        if (nullptr == output_file) {
            fprintf(stderr, "Can't open output file %s.\n", output_filename);
            perror("Fatal error");
            exit(1);
        }

        uint32_t size = 0;
        if (candidates_remaining == 0) {
            break;
        } else if (candidates_remaining >= FLAGS_shard_size) {
            size = FLAGS_shard_size;
        } else {
            size = candidates_remaining;
        }

        shard_end += size;

        write_word(output_file, size);
        for (uint32_t i = 0; i < size; ++i) {
            write_candidate(output_file, candidates[i]);
        }

        candidates_remaining -= size;
        fclose(output_file);

        if (correct_index != -1 && shard_start < correct_index &&
            shard_end > correct_index) {
            printf("Shard %s contains the correct guess.", output_filename);
        }

        shard_index += 1;
        shard_start += size;
    }
}

// info: the info about the archive to attack
// table: vector<vector<stage1a>> table(0x01000000)
void mitm_stage1a(archive_info &info, vector<vector<stage1a>> &table,
                  correct_guess *c) {
    // STAGE 1
    //
    // Guess s0, chunk2, chunk3 and carry bits.
    uint8_t xf0 = info.file[0].x[0];
    uint8_t xf1 = info.file[1].x[0];
    uint32_t extra(0);

    for (uint16_t s0 = 0; s0 < 0x100; ++s0) {
        fprintf(stderr, "%02x ", s0);
        if ((s0 & 0xf) == 0xf) {
            fprintf(stderr, "\n");
        }
        for (uint16_t chunk2 = 0; chunk2 < 0x100; ++chunk2) {
            for (uint16_t chunk3 = 0; chunk3 < 0x100; ++chunk3) {
                for (uint8_t carries = 0; carries < 0x10; ++carries) {
                    if (nullptr != c && s0 == c->sx[0][0] &&
                        chunk2 == c->chunk2 && chunk3 == c->chunk3 &&
                        carries == (c->carries >> 12)) {
                        fprintf(stderr, "On correct guess.\n");
                    }
                    uint8_t carryxf0 = carries & 1;
                    uint8_t carryyf0 = (carries >> 1) & 1;
                    uint8_t carryxf1 = (carries >> 2) & 1;
                    uint8_t carryyf1 = (carries >> 3) & 1;
                    uint32_t upper = 0x01000000;  // exclusive
                    uint32_t lower = 0x00000000;  // inclusive

                    uint32_t k0crc = chunk2;
                    uint32_t extra = 0;
                    uint8_t msbxf0 =
                        first_half_step(xf0, false, chunk3, carryxf0, k0crc,
                                        extra, upper, lower);
                    uint8_t yf0 = xf0 ^ s0;
                    k0crc = chunk2;
                    extra = 0;
                    uint8_t msbyf0 =
                        first_half_step(yf0, false, chunk3, carryyf0, k0crc,
                                        extra, upper, lower);
                    if (upper < lower) {
                        if (nullptr != c && s0 == c->sx[0][0] &&
                            chunk2 == c->chunk2 && chunk3 == c->chunk3 &&
                            carries == (c->carries >> 12)) {
                            fprintf(stderr,
                                    "Failed to get correct guess: s0 = %02x, "
                                    "chunk2 = %02x, "
                                    "chunk3 = "
                                    "%02x, carries = %x\n",
                                    s0, chunk2, chunk3, carries);
                        }
                        continue;
                    }
                    k0crc = chunk2;
                    extra = 0;
                    uint8_t msbxf1 =
                        first_half_step(xf1, false, chunk3, carryxf1, k0crc,
                                        extra, upper, lower);
                    if (upper < lower) {
                        if (nullptr != c && s0 == c->sx[0][0] &&
                            chunk2 == c->chunk2 && chunk3 == c->chunk3 &&
                            carries == (c->carries >> 12)) {
                            fprintf(stderr,
                                    "Failed to get correct guess: s0 = %02x, "
                                    "chunk2 = %02x, "
                                    "chunk3 = "
                                    "%02x, carries = %x\n",
                                    s0, chunk2, chunk3, carries);
                        }
                        continue;
                    }
                    uint8_t yf1 = xf1 ^ s0;
                    k0crc = chunk2;
                    extra = 0;
                    uint8_t msbyf1 =
                        first_half_step(yf1, false, chunk3, carryyf1, k0crc,
                                        extra, upper, lower);
                    if (upper < lower) {
                        if (nullptr != c && s0 == c->sx[0][0] &&
                            chunk2 == c->chunk2 && chunk3 == c->chunk3 &&
                            carries == (c->carries >> 12)) {
                            fprintf(stderr,
                                    "Failed to get correct guess: s0 = %02x, "
                                    "chunk2 = %02x, "
                                    "chunk3 = "
                                    "%02x, carries = %x\n",
                                    s0, chunk2, chunk3, carries);
                        }
                        continue;
                    }
                    uint32_t mk = toMapKey(msbxf0, msbyf0, msbxf1, msbyf1);
                    if (nullptr != c && s0 == c->sx[0][0] &&
                        chunk2 == c->chunk2 && chunk3 == c->chunk3 &&
                        carries == (c->carries >> 12)) {
                        fprintf(stderr,
                                "MSBs: %02x, %02x, %02x, %02x, Mapkey: %08x, "
                                "carries: %x, "
                                "c.carries: %04x\n",
                                msbxf0, msbyf0, msbxf1, msbyf1, mk, carries,
                                c->carries);
                    }
                    stage1a candidate = {uint8_t(s0), uint8_t(chunk2),
                                         uint8_t(chunk3), carries, msbxf0};
                    table[mk].push_back(candidate);
                }
            }
        }
    }
}

// info: the info about the archive to attack
// table: the output of mitm_stage1a
// candidates: an empty vector
// preimages: generated by build_preimages
void mitm_stage1b(archive_info &info, vector<vector<stage1a>> &table,
                  vector<stage1_candidate> &candidates,
                  vector<vector<uint16_t>> &preimages, correct_guess *c,
                  size_t *correct_candidate_index) {
    // Second half of MITM for stage 1
    bool found_correct = false;
    for (uint16_t s1xf0 = 0; s1xf0 < 0x100; ++s1xf0) {
        for (uint8_t prefix = 0; prefix < 0x40; ++prefix) {
            uint16_t pxf0(preimages[s1xf0][prefix]);
            if (nullptr != c && s1xf0 == c->sx[0][1]) {
                fprintf(stderr, "s1xf0: %02x, prefix: %04x    ", s1xf0, pxf0);
                if ((prefix & 3) == 3) {
                    fprintf(stderr, "\n");
                }
            }
            vector<uint8_t> firsts(0);
            uint8_t s1yf0 = s1xf0 ^ info.file[0].x[1] ^ info.file[0].h[1];
            second_half_step(pxf0, s1yf0, firsts, preimages);
            if (!firsts.size()) {
                continue;
            }
            for (uint16_t s1xf1 = 0; s1xf1 < 0x100; ++s1xf1) {
                vector<uint8_t> seconds(0);
                second_half_step(pxf0, s1xf1, seconds, preimages);
                if (!seconds.size()) {
                    continue;
                }
                vector<uint8_t> thirds(0);
                uint8_t s1yf1 = s1xf1 ^ info.file[1].x[1] ^ info.file[1].h[1];
                second_half_step(pxf0, s1yf1, thirds, preimages);
                if (!thirds.size()) {
                    continue;
                }
                for (auto f : firsts) {
                    for (auto s : seconds) {
                        for (auto t : thirds) {
                            uint32_t mapkey(f | (s << 8) | (t << 16));
                            for (stage1a candidate : table[mapkey]) {
                                stage1_candidate g;
                                g.chunk2 = candidate.chunk2;
                                g.chunk3 = candidate.chunk3;
                                g.cb1 = candidate.cb;
                                g.m1 =
                                    (candidate.msbk11xf0 * 0x01010101) ^ mapkey;

                                // Get ~4 possible solutions for lo24(k20) =
                                // chunks 1 and 4
                                //       A  B  C  D   k20
                                // ^  E  F  G  H      crc32tab[D]
                                //    ----------
                                //    I  J  K  L      crck20
                                // ^  M  N  O  P      crc32tab[msbk11xf0]
                                //    ----------
                                //    Q  R  S  T      (pxf0 << 2) matches k21xf0

                                // Starting at the bottom, derive 15..2 of KL
                                // from 15..2 of ST and OP
                                uint16_t crck20 =
                                    ((pxf0 << 2) ^
                                     crc32tab[candidate.msbk11xf0]) &
                                    0xfffc;

                                // Now starting at the top, iterate over 64
                                // possibilities for 15..2 of CD
                                for (uint8_t i = 0; i < 64; ++i) {
                                    uint32_t maybek20 =
                                        (preimages[candidate.s0][i] << 2);
                                    // and 4 possibilities for low two bits of D
                                    for (uint8_t lo = 0; lo < 4; ++lo) {
                                        // CD
                                        maybek20 = (maybek20 & 0xfffc) | lo;
                                        // L' = C ^ H
                                        uint8_t match =
                                            (maybek20 >> 8) ^
                                            crc32tab[maybek20 & 0xff];
                                        // If upper six bits of L == upper six
                                        // of L' then we have a candidate
                                        if ((match & 0xfc) == (crck20 & 0xfc)) {
                                            // KL ^ GH = BC.  (B = BC >> 8) &
                                            // 0xff.
                                            uint8_t b =
                                                ((crck20 ^
                                                  crc32tab[maybek20 & 0xff]) >>
                                                 8) &
                                                0xff;

                                            if (g.k20_count >= g.MAX_K20S) {
                                                fprintf(stderr,
                                                        "Not enough space for "
                                                        "k20 candidate in "
                                                        "stage1_candidate.\n");
                                                abort();
                                            }

                                            // BCD = (B << 16) | CD
                                            g.maybek20[g.k20_count] =
                                                (b << 16) | maybek20;
                                            g.k20_count += 1;
                                        }
                                    }
                                }

                                if (0 == g.k20_count) {
                                    continue;
                                }

                                candidates.push_back(g);

                                if (nullptr != c && s1xf0 == c->sx[0][1] &&
                                    s1xf1 == c->sx[1][1] &&
                                    candidate.s0 == c->sx[0][0] &&
                                    candidate.chunk2 == c->chunk2 &&
                                    candidate.chunk3 == c->chunk3 &&
                                    candidate.cb == (c->carries >> 12)) {
                                    found_correct = true;
                                    fprintf(stderr,
                                            "Correct candidates index = %lx\n",
                                            candidates.size() - 1);
                                    if (nullptr != correct_candidate_index) {
                                        *correct_candidate_index =
                                            candidates.size() - 1;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if (c != nullptr && !found_correct) {
        fprintf(stderr,
                "Failed to use correct guess: s1xf0 = %02x, s1xf1 = %02x\n",
                c->sx[0][1], c->sx[1][1]);
    }
    fprintf(stderr, "Stage 1 candidates.size() == %04lx\n", candidates.size());
}

};  // namespace mitm_stage1
