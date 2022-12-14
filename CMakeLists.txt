cmake_minimum_required(VERSION 3.0.0)
project(DOS VERSION 0.1.0)

aux_source_directory (./source/src DIR_SRC)

include_directories (./source/inc)

include(CTest)
enable_testing()

add_executable(${PROJECT_NAME} ${DIR_SRC})

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)

if(MSVC)
    target_compile_options(${PROJECT_NAME} PRIVATE /W4 /WX)
else()
    target_compile_options(${PROJECT_NAME} PRIVATE -Wall -Wextra -pedantic)
endif()

target_link_libraries(${PROJECT_NAME} pthread)

set (EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin)