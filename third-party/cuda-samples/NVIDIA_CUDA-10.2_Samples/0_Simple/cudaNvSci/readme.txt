Sample: cudaNvSci
Minimum spec: SM 6.0

This sample demonstrates CUDA-NvSciBuf/NvSciSync Interop. Two CPU threads import the NvSciBuf and NvSciSync into CUDA to perform two image processing algorithms on a ppm image - image rotation in 1st thread & rgba to grayscale conversion of rotated image in 2nd thread.

Key concepts:
CUDA NvSci Interop
Data Parallel Algorithms
Image Processing
