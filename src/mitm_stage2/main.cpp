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
DEFINE_int32(stage2_candidates_per_stage1_candidate, 10000,
             "An estimate of the maximum number of stage2 candidates per stage1 "
             "candidate.");
DEFINE_int32(stage2_shard_size, 1000000, "Size of a stage2 shard.");

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


class stage2_candidate_array {
public:
    stage2_candidate_array() : ptr_(nullptr), size_(0), count_(0) {
        if (0 < FLAGS_stage2_shard_size) {
            ptr_ = (stage2_candidate *)::calloc(FLAGS_stage2_shard_size, sizeof(stage2_candidate));
            if (nullptr == ptr_) {
                std::bad_alloc ex;
                throw ex;
            }
            size_ = FLAGS_stage2_shard_size;
        } else {
            std::bad_alloc ex;
            throw ex;
        }
    }

    stage2_candidate_array(size_t x) : ptr_(nullptr), size_(0), count_(0) {
        ptr_ = (stage2_candidate *)::calloc(x, sizeof(stage2_candidate));
        if (nullptr == ptr_) {
            std::bad_alloc ex;
            throw ex;
        }
        size_ = x;
    }

    size_t size() { return size_; }
    size_t count() { return count_; }
    void incr(size_t x) { count_ += x; }
    stage2_candidate *ptr() { return ptr_; }

    bool merge(const stage2_candidate_array &other) {
        // TODO: try a realloc?
        if (count_ + other.count_ > size_) {
            fprintf(stderr, "merge: can't merge: size_=%lu, current count=%lu, merge count=%lu\n",
                    size_, count_, other.count_);
            return false;
        }
       
        ::memcpy(ptr_ + count_, other.ptr_, sizeof(stage2_candidate) * other.count_);
        count_ += other.count_;
        return true;
    }

    void clear() {
        ::memset((void *)ptr_, 0, sizeof(stage2_candidate) * size_);
        count_ = 0;
    }

private:
    stage2_candidate *ptr_;
    size_t size_, count_;
};


void merge_candidates(/* out */ stage2_candidate_array &stage2_candidates,
                      const stage2_candidate_array &stage2_tmp_array,
                      /* out */ size_t &idx,
                      const size_t &stage2b_count,
                      const correct_guess *guess = nullptr) {
    if (false == stage2_candidates.merge(stage2_tmp_array)) {
        // Output the current shard, however many elements it has.
        fprintf(stderr, "Emitting shard %lu with %lu elements.\n", idx, stage2_candidates.count());
        if (nullptr != guess) {
            write_stage2_candidates(stage2_candidates.ptr(), stage2_candidates.count(),
                                    idx, guess);
        } else {
            write_stage2_candidates(stage2_candidates.ptr(), stage2_candidates.count(), idx);
        }

        stage2_candidates.clear();
        if (false == stage2_candidates.merge(stage2_tmp_array)) {
            fprintf(stderr, "FATAL: Failed to merge arrays after clear.\n");
            exit(-1);
        }

        // Increment the shard number.
        idx += 1;
    }

    printf("shard[%lu] => %lu more candidates, %lu total.\n", idx,
           stage2b_count, stage2_candidates.count());
    fflush(stdout);
}

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

    stage2_candidate_array stage2_candidates;
    stage2_candidate_array stage2_tmp_array(FLAGS_stage2_candidates_per_stage1_candidate);

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

    printf("Read %ld candidates from stage1.\n", candidates.size());
    printf("Starting stage2...\n  * Stage2 shards will be no larger than %d candidates.\n",
           FLAGS_stage2_shard_size);

    if (FLAGS_runtests) {
        correct_guess guess[1] = {
            correct(mitm::test[0])};  //,
                                      // correct(mitm::test[1])};

        size_t idx = 0;
        size_t stage2_candidate_total = 0;
        size_t current_stage1_cand = 0;

        for (auto candidate : candidates) {
            stage2_tmp_array.clear();
            printf("On stage1 candidate %lu of %lu.\n", current_stage1_cand, candidates.size());

            vector<vector<stage2a>> table(0x1000000);
            mitm_stage2a(test[0], candidate, table, guess);
            
            size_t stage2b_count = 0;
            mitm_stage2b(test[0], candidate, table, stage2_tmp_array.ptr(),
                         stage2_tmp_array.size(), stage2b_count, guess);
            stage2_tmp_array.incr(stage2b_count);
            stage2_candidate_total += stage2b_count;

            merge_candidates(stage2_candidates, stage2_tmp_array, idx, stage2b_count);

            if (FLAGS_stop_after <= stage2_candidate_total) {
                fprintf(stderr, "Stopping after %d candidates. Goodbye.\n",
                        (int)idx);
                break;
            }

            ++current_stage1_cand;
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

        size_t current_stage1_cand = 0;
        for (auto candidate : candidates) {
            printf("On stage1 candidate %lu of %lu.\n", current_stage1_cand, candidates.size());
            stage2_tmp_array.clear();
#ifdef DEBUG
            fprintf(stderr, "Stage 1 candidate:\nmaybek20s: ");
            for (int i = 0; i < candidate.k20_count; ++i) {
                fprintf(stderr, "%08x, ", candidate.maybek20[i]);
            }
            fprintf(stderr, "\nch2: %02x, ch3: %02x, cb1: %x, m1: %08x\n",
                    candidate.chunk2, candidate.chunk3, candidate.cb1,
                    candidate.m1);
#endif

            vector<vector<stage2a>> table(0x1000000);
            mitm_stage2a(archive, candidate, table);

            size_t stage2b_count = 0;
            mitm_stage2b(archive, candidate, table, stage2_tmp_array.ptr(),
                         stage2_tmp_array.size(), stage2b_count);
            stage2_tmp_array.incr(stage2b_count);
            stage2_candidate_total += stage2b_count;

            merge_candidates(stage2_candidates, stage2_tmp_array, idx, stage2b_count);

            if (FLAGS_stop_after <= idx) {
                fprintf(stderr, "Stopping after %d candidates. Goodbye.\n",
                        (int)idx);
                break;
            }

            ++current_stage1_cand;
        }
    }

    // TODO(stay): Close open files.
    return 0;
}
