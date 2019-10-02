set(tests check_simple check_header)

foreach(test ${tests})
    add_executable(${test} ${test}.cpp)
    target_link_libraries(${test} breakzipcore ${LIBS})
    add_test(NAME ${test}_test COMMAND ${test} PROPERTIES TIMEOUT 10)
endforeach()

