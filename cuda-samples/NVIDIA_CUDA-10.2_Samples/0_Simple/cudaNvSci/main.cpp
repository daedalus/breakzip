/*
 * Copyright 1993-2019 NVIDIA Corporation.  All rights reserved.
 *
 * Please refer to the NVIDIA end user license agreement (EULA) associated
 * with this source code for terms and conditions that govern your use of
 * this software. Any use, reproduction, disclosure, or distribution of
 * this software and related documentation outside the terms of the EULA
 * is strictly prohibited.
 *
 */

#include <cuda.h>
#include <vector>
#include "cudaNvSci.h"
#include <helper_cuda.h>
#include <helper_image.h>

void loadImageData(const std::string& filename, const char **argv, unsigned char **image_data, uint32_t &imageWidth, uint32_t &imageHeight) 
{
    // load image (needed so we can get the width and height before we create
    // the window
    char* image_path = sdkFindFilePath(filename.c_str(), argv[0]);

    if (image_path == 0) {
      printf("Error finding image file '%s'\n", filename.c_str());
      exit(EXIT_FAILURE);
    }

    sdkLoadPPM4(image_path, image_data, &imageWidth,
                &imageHeight);

    if (!image_data) {
      printf("Error opening file '%s'\n", image_path);
      exit(EXIT_FAILURE);
    }

    printf("Loaded '%s', %d x %d pixels\n", image_path, imageWidth,
           imageHeight);
}

int main(int argc, const char **argv)
{
    int numOfGPUs = 0;
    std::vector<int> deviceIds;
    checkCudaErrors(cudaGetDeviceCount(&numOfGPUs));

    printf("%d GPUs found\n", numOfGPUs);
    if (!numOfGPUs)
    {
        exit(EXIT_WAIVED);
    }
    else
    {
        for (int devID = 0; devID < numOfGPUs; devID++)
        {
            int major = 0, minor = 0; 
            checkCudaErrors(cudaDeviceGetAttribute(&major, cudaDevAttrComputeCapabilityMajor, devID));
            checkCudaErrors(cudaDeviceGetAttribute(&minor, cudaDevAttrComputeCapabilityMinor, devID));
            if (major >= 6)
            {
                deviceIds.push_back(devID);
            }
        }
        if (deviceIds.size() == 0)
        {
            printf("cudaNvSci requires one or more GPUs of Pascal(SM 6.0) or higher archs\nWaiving..\n");
            exit(EXIT_WAIVED);
        }
    }

    std::string image_filename = "lenaRGB.ppm";

    if (checkCmdLineFlag(argc, (const char**)argv, "file")) {
        getCmdLineArgumentString(argc, (const char**)argv, "file", (char**)&image_filename);
    }

    uint32_t imageWidth = 0;
    uint32_t imageHeight = 0;
    unsigned char *image_data = NULL;

    loadImageData(image_filename, argv, &image_data, imageWidth, imageHeight);

    cudaNvSci cudaNvSciApp(deviceIds.size() > 1, deviceIds, image_data, imageWidth, imageHeight);
    cudaNvSciApp.runCudaNvSci(image_filename);

    return EXIT_SUCCESS;
}