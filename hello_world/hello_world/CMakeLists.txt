# CMakeList.txt: hello_world 的 CMake 项目，在此处包括源代码并定义
# 项目特定的逻辑。
#
cmake_minimum_required (VERSION 3.21)

set(CMAKE_C_VISIBILITY_PRESET hidden)
set(CMAKE_CXX_VISIBILITY_PRESET hidden)
set(CMAKE_ANDROID_STL_TYPE c++_shared)
set(CMAKE_CXX_STANDARD 17)

if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    message(STATUS "=== Debug Mode ===")
    #set(LINK_FLAGS "-fsanitize=address")
    #set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address -fno-omit-frame-pointer")
else()
    message(STATUS "=== Remove debug information and symbols ===")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Oz -flto -fdata-sections -ffunction-sections")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Oz -flto -fdata-sections -ffunction-sections")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -s -Wl,--exclude-libs,ALL -flto")
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -s -Wl,--exclude-libs,ALL -Wl,--gc-sections -flto")
endif()

set(LIBRARY_NAME hello_world)
message("Building library: ${LIBRARY_NAME}")

set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${LINK_FLAGS}")
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} ${LINK_FLAGS}")

# 添加头文件目录
include_directories(
    .
)

# 将源代码添加到此项目的可执行文件。
aux_source_directory(. project_src)

add_executable (
    ${LIBRARY_NAME}
    ${project_src}
)

target_link_libraries(${LIBRARY_NAME} log)
find_package(ZLIB)
include_directories(${ZLIB_INCLUDE_DIR})
target_link_libraries(${LIBRARY_NAME} ${ZLIB_LIBRARIES})