# Author: Nash E. Foster

add_library(mitm_stage2_core mitm_stage2.cpp)

add_executable(mitm_stage2 main.cpp)
target_link_libraries(mitm_stage2 mitm_stage2_core breakzipcore ${LIBS})

install(TARGETS mitm_stage2 mitm_stage2_core
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib/breakziplib)

