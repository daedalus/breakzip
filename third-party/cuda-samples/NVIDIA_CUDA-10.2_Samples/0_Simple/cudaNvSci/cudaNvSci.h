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
#ifndef CUDANVSCI_H
#define CUDANVSCI_H

#include <nvscibuf.h>
#include <nvscisync.h>
#include <cuda_runtime.h>
#include <helper_cuda.h>
#include <vector>

#define checkNvSciErrors(call) do {                             \
    NvSciError _status = call;                                                \
    if( NvSciError_Success != _status) {                                      \
        printf("NVSCI call in file '%s' in line %i returned"                 \
            " %d, expected %d\n",                                           \
            __FILE__, __LINE__, _status, NvSciError_Success); fflush(stdout);  \
    exit(EXIT_FAILURE); }  } while (0)


extern void rotateKernel(cudaTextureObject_t &texObj, const float angle, unsigned int *d_outputData, 
                            const int imageWidth, const int imageHeight, cudaStream_t stream);
extern void launchGrayScaleKernel(unsigned int* d_rgbaImage, std::string image_filename, size_t imageWidth, 
                                    size_t imageHeight, cudaStream_t stream);

class cudaNvSci
{
private:
    int m_isMultiGPU;
    int m_cudaNvSciSignalDeviceId;
    int m_cudaNvSciWaitDeviceId;
    unsigned char *image_data;
    size_t m_bufSize;
    size_t imageWidth;
    size_t imageHeight;

public:
    NvSciSyncModule syncModule;
    NvSciBufModule buffModule;
    NvSciSyncAttrList syncUnreconciledList[2];
    NvSciSyncAttrList syncReconciledList;
    NvSciSyncAttrList syncConflictList;

    NvSciBufAttrList rawBufUnreconciledList[2];
    NvSciBufAttrList imageBufUnreconciledList[2];
    NvSciBufAttrList rawBufReconciledList;
    NvSciBufAttrList buffConflictList;
    NvSciBufAttrList imageBufReconciledList;
    NvSciBufAttrList imageBufConflictList;
    NvSciBufAttrList buffAttrListOut;

    NvSciSyncObj    syncObj;
    NvSciBufObj     rawBufObj;
    NvSciBufObj     imageBufObj;
    NvSciSyncFence  *fence;

    cudaNvSci(int isMultiGPU, std::vector<int> &deviceIds, unsigned char *image_data, size_t imageWidth, size_t imageHeight);

    void initNvSci();

    void runCudaNvSci(std::string& image_filename);

    void createNvSciRawBufObj();

    void createNvSciSyncObj();

    void createNvSciBufImageObj();
};

#endif // CUDANVSCI_H


