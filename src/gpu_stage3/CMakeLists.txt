# Author: Nash E. Foster

add_library(cpu_stage3_core cpu_stage3.cpp)
add_library(cuda_stage3_core gpu_stage3.cu)

add_executable(cpu_stage3 main.cpp)
target_link_libraries(cpu_stage3 mitm_stage1_core mitm_stage2_core
                      cpu_stage3_core breakzipcore ${LIBS})

add_executable(cuda_stage3 cuda_main.cu)
target_link_libraries(cuda_stage3 mitm_stage1_core mitm_stage2_core
                      cuda_stage3_core breakzipcore ${LIBS})

install(TARGETS cpu_stage3 cpu_stage3_core cuda_stage3 cuda_stage3_core
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib/breakziplib)

