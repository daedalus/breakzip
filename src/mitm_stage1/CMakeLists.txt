# Author: Nash E. Foster

add_library(mitm_stage1_core crc32.cpp mitm_stage1.cpp)

add_executable(mitm_stage1 main.cpp)
target_link_libraries(mitm_stage1 mitm_stage1_core breakzipcore ${LIBS})

install(TARGETS mitm_stage1 mitm_stage1_core
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib/breakziplib)

