# Author: Nash E. Foster

add_subdirectory(test)
add_subdirectory(mitm_stage1)
add_subdirectory(mitm_stage2)
add_subdirectory(gpu_stage3)

configure_file(breakzip_config.h.in breakzip_config.h)
add_library(breakzipcore breakzip.cpp crc32.cpp mitm_common.cpp preimages_table.cpp)

add_executable(breakzip main.cpp)
target_link_libraries(breakzip breakzipcore ${LIBS})

add_executable(recoverseed recoverseed.cpp)
target_link_libraries(recoverseed breakzipcore ${LIBS})

add_executable(preimages preimages.cpp)
target_link_libraries(preimages breakzipcore ${LIBS})

install(TARGETS breakzip recoverseed breakzipcore
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib/breakziplib)

find_package(Doxygen)
if(DOXYGEN_FOUND)
    configure_file(${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile.in
        ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile @ONLY)
    add_custom_target(doc
        ${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        COMMENT "Generating API docs w/Doxygen" VERBATIM)
endif(DOXYGEN_FOUND)

