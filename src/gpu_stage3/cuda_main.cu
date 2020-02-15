#include <algorithm>
#include <stdio.h>
#include <stdlib.h>

#include "stage3.h"

#include <cuda.h>
#include <cuda_runtime.h>
#include <cuda_runtime_api.h>

DECLARE_string(target);
DECLARE_bool(runtests);
DEFINE_string(input_shard, "target.out.0",
              "The filename of the stage1 shard to run on.");
DECLARE_string(output);
DECLARE_int32(srand_seed);
DEFINE_int32(stop_after, -1,
             "If set to a positive value, the program "
             "will stop after processing <stop_after> stage1 candidates.");
DEFINE_int32(cuda_device, -1,
             "Which CUDA device to use, -1 to use them all.");

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

// Print device properties
void print_device_properties(cudaDeviceProp devProp) {
    printf("Major revision number:         %d\n",  devProp.major);
    printf("Minor revision number:         %d\n",  devProp.minor);
    printf("Name:                          %s\n",  devProp.name);
    printf("Total global memory:           %lu\n",  devProp.totalGlobalMem);
    printf("Total shared memory per block: %lu\n",  devProp.sharedMemPerBlock);
    printf("Total registers per block:     %d\n",  devProp.regsPerBlock);
    printf("Warp size:                     %d\n",  devProp.warpSize);
    printf("Maximum memory pitch:          %lu\n",  devProp.memPitch);
    printf("Maximum threads per block:     %d\n",  devProp.maxThreadsPerBlock);
    printf("Maximum threads per multiproc: %d\n", devProp.maxThreadsPerMultiProcessor);

    for (int i = 0; i < 3; ++i) {
        printf("Maximum dimension %d of block:  %d\n", i, devProp.maxThreadsDim[i]);
    }

    for (int i = 0; i < 3; ++i) {
        printf("Maximum dimension %d of grid:   %d\n", i, devProp.maxGridSize[i]);
    }

    printf("Clock rate:                    %d\n",  devProp.clockRate);
    printf("Total constant memory:         %lu\n",  devProp.totalConstMem);
    printf("Texture alignment:             %lu\n",  devProp.textureAlignment);
    printf("Concurrent copy and execution: %s\n",  (devProp.deviceOverlap ? "Yes" : "No"));
    printf("Number of multiprocessors:     %d\n",  devProp.multiProcessorCount);
    printf("Kernel execution timeout:      %s\n",  (devProp.kernelExecTimeoutEnabled ? "Yes" : "No"));
    printf("\n\n");
    return;
}

__global__ void gpu_stage3_kernel(const gpu_stage2_candidate *candidates,
                                  keys *results,
                                  const archive_info* archive,
                                  const uint32_t stage2_candidate_count,
                                  const mitm::correct_guess& c) {
    int i = blockIdx.x + blockDim.x * threadIdx.x;
    if (i < stage2_candidate_count) {
        keys result = {0, 0, 0};
        stage3::gpu_stage3_internal(*archive, candidates[i], &result, &c);

        if (result.crck00 != 0 || result.k10 != 0 || result.k20 != 0) {
            results[i].crck00 = 1;
            results[i].k10 = 0;
            results[i].k20 = 0;
        } else {
            results[i].crck00 = 0;
            results[i].k10 = 0;
            results[i].k20 = 0;
        }
    }
}

int main(int argc, char *argv[]) {
    int my_argc = argc;

    SetVersionString(version_string());
    SetUsageMessage(usage_message);
    auto non_flag = ParseCommandLineFlags(&my_argc, &argv, false);

    // We build the preimages once for all candidates.
    vector<vector<uint16_t>> preimages(0x100);
    build_preimages(preimages);

    gpu_stage2_candidate *stage2_candidates = nullptr;
    uint32_t stage2_candidate_count = 0;
    size_t candidate_array_size = 0;
    read_stage2_candidates_for_gpu(&stage2_candidates, &stage2_candidate_count, candidate_array_size);
    size_t results_array_size = sizeof(keys) * stage2_candidate_count;

    if (0 == stage2_candidate_count) {
        fprintf(stderr, "FATAL: Read no candidates from input file.\n");
        exit(-1);
    }

    if (nullptr == stage2_candidates) {
        fprintf(stderr, "FATAL: Stage2 candidate array was null.\n");
        exit(-1);
    }

    fprintf(stdout, "Read %d candidates from stage2.\n",
            stage2_candidate_count);

    archive_info archive;
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

    int cuda_device_count = 0;
    cudaGetDeviceCount(&cuda_device_count);

    if (0 == cuda_device_count) {
        fprintf(stderr, "Host has no CUDA capable devices. Use cpu_stage3, instead?\n");
        exit(-1);
    }

    vector<int> target_devices;
    int cuda_device = 0;
    for (cuda_device = 0; cuda_device < cuda_device_count; ++cuda_device) {
        struct cudaDeviceProp prop;
        cudaGetDeviceProperties(&prop, cuda_device);
        fprintf(stderr, "CUDA Device %d: %s\n", cuda_device, prop.name);
        print_device_properties(prop);
        
        // TODO(leaf): Check capabilities for what we need?
        if (-1 == FLAGS_cuda_device) {
            target_devices.push_back(cuda_device);
            fprintf(stderr, "Targeting CUDA device %d\n", cuda_device);
        } else if (FLAGS_cuda_device == cuda_device) {
            target_devices.push_back(cuda_device);
            fprintf(stderr, "stage3 will target CUDA device %d\n", cuda_device);
        } else {
            fprintf(stderr, "Ignoring CUDA device %d\n", cuda_device);
        }

        fprintf(stderr, "\n");
    }

    fprintf(stderr, "CUDA stage3 targeting these devices: ");
    for_each(target_devices.begin(), target_devices.end(),
             [](const auto &e) { fprintf(stderr, "%d ", e); });
    fprintf(stderr, "\n");

    for (auto device: target_devices) {
        fprintf(stderr, "Initialization device %d...\n", device);
        auto err = cudaSetDevice(device);
        if (cudaSuccess != err) {
            fprintf(stderr, "Failed to set active CUDA device %d: %s\n",
                    device, cudaGetErrorString(err));
            exit(-1);
        }

        // Allocate host memory for results
        keys *host_results = (keys *)::calloc(stage2_candidate_count, sizeof(keys));
        if (nullptr == host_results) {
            fprintf(stderr, "Failed to allocate host memory for result set.\n");
            exit(-1);
        }

        archive_info *dev_archive = nullptr;
        err = cudaMalloc(&dev_archive, sizeof(archive_info));
        if (cudaSuccess != err) {
            fprintf(stderr, "Failed to allocate memory for archive on device %d\n", device);
            exit(-1);
        }
        err = cudaMemcpy(dev_archive, &archive, sizeof(archive_info), cudaMemcpyHostToDevice);
        if (cudaSuccess != err) {
            fprintf(stderr, "Failed to memcpy archive to CUDA device %d\n", device);
            exit(-1);
        }

        // Allocate device memory
        gpu_stage2_candidate *dev_cands = nullptr;
        keys *dev_results = nullptr;
        fprintf(stderr, "Allocating candidate array of size %ld on device %d\n",
                candidate_array_size, device);
        err = cudaMalloc(&dev_cands, candidate_array_size);
        if (cudaSuccess != err) {
            fprintf(stderr, "Failed to allocate memory on CUDA device %d: %s\n",
                    device, cudaGetErrorString(err));
            exit(-1);
        }

        if (nullptr == dev_cands) {
            fprintf(stderr, "Device allocation failed, array is null!\n");
            exit(-1);
        }

        fprintf(stderr, "Allocating results array of size %ld on device %d\n", results_array_size, device);
        err = cudaMalloc(&dev_results, results_array_size);
        if (cudaSuccess != err) {
            fprintf(stderr, "Failed to allocate memory on CUDA device %d: %s\n",
                    device, cudaGetErrorString(err));
            cudaFree(dev_cands);
            exit(-1);
        }

        // Copy candidates to device
        fprintf(stderr, "Copying candidate data to device %d\n", device);
        err = cudaMemcpy(dev_cands, stage2_candidates, candidate_array_size, cudaMemcpyHostToDevice);
        if (cudaSuccess != err) {
            fprintf(stderr, "Failed to memcpy data to CUDA device %d: %s\n",
                    device, cudaGetErrorString(err));
            exit(-1);
        }

        // Call kernel
        fprintf(stderr, "Calling kernel:\n  Host results @ %p\n  Dev  results @ %p\n  Results size: %ld\n",
                host_results, dev_results, results_array_size);
        fprintf(stderr, "  Dec candidates @ %p\n  Stage2 candidates: %u\n", dev_cands, stage2_candidate_count);

        int block_size = 0;
        int min_grid_size = 0;
        int grid_size = 0;

        cudaOccupancyMaxPotentialBlockSize(&min_grid_size, &block_size, (void*)gpu_stage3_kernel, 0, stage2_candidate_count);

        fprintf(stderr, "Est.   BlockSize: block_sz=%d min_grid_sz=%d grid_size=%d\n", block_size, min_grid_size, grid_size);
        //round up
        grid_size = (stage2_candidate_count + block_size - 1) / block_size;
        fprintf(stderr, "Actual BlockSize: block_sz=%d min_grid_sz=%d grid_size=%d\n", block_size, min_grid_size, grid_size);


        gpu_stage3_kernel<<<grid_size, block_size>>>(dev_cands, dev_results, dev_archive, stage2_candidate_count, *c);
        err = cudaGetLastError();
        if (cudaSuccess != err) {
            fprintf(stderr, "CUDA Kernel failed: %s\n", cudaGetErrorString(err));
            cudaFree(dev_cands);
            cudaFree(dev_results);
            free(host_results);
            exit(-1);
        }

        // Copy results to host.
        err = cudaMemcpy(host_results, dev_results, results_array_size, cudaMemcpyDeviceToHost);
        if (cudaSuccess != err) {
            fprintf(stderr, "Failed to copy results to host: %s\n",
                    cudaGetErrorString(err));
            fprintf(stderr, "  Host results @ %p\n", host_results);
            fprintf(stderr, "  Dev  results @ %p\n", dev_results);
            fprintf(stderr, "  Results size: %ld\n", results_array_size);
            cudaFree(dev_cands);
            cudaFree(dev_results);
            free(host_results);
            exit(-1);
        }

        bool success = false;
        for (int i = 0; i < stage2_candidate_count; ++i) {
            if (host_results[i].crck00 != 0 || host_results[i].k10 != 0 || host_results[i].k20 != 0) {
                fprintf(stdout, "FINAL: Success! Keys: crck00=%u k10=%u k20=%u\n", 
                        host_results[i].crck00,
                        host_results[i].k10,
                        host_results[i].k20);
                success = true;
                break;
            }
        }

        if (!success) {
            fprintf(stderr, "FINAL: Results check complete, no keys found.\n");
        }

        // Free memory on device.
        err = cudaFree(dev_cands);
        if (cudaSuccess != err) {
            fprintf(stderr, "Failed to free device memory on %d: %s\n",
                    device, cudaGetErrorString(err));
            exit(-1);
        }

        err = cudaFree(dev_results);
        if (cudaSuccess != err) {
            fprintf(stderr, "Failed to free device memory on %d: %s\n",
                    device, cudaGetErrorString(err));
            exit(-1);
        }

        err = cudaFree(dev_archive);
        if (cudaSuccess != err) {
            fprintf(stderr, "Failed to free device memory on %d: %s\n",
                    device, cudaGetErrorString(err));
            exit(-1);
        }
    }

    exit(0);
}
