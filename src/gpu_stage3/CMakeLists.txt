# Author: Nash E. Foster

add_library(gpu_stage3_core gpu_stage3.cpp)

add_executable(gpu_stage3 main.cpp)
target_link_libraries(gpu_stage3 mitm_stage1_core mitm_stage2_core gpu_stage3_core
                      breakzipcore ${LIBS})

install(TARGETS gpu_stage3 gpu_stage3_core
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib/breakziplib)

