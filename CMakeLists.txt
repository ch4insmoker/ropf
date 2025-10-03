project(ropf)
cmake_minimum_required(VERSION 3.10)

if (Windows)
  set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)
endif ()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED TRUE)

include_directories(${CMAKE_CURRENT_LIST_DIR}/third_party/capstone/include)
add_compile_definitions(CAPSTONE_HAS_X86 CAPSTONE_HAS_AARCH64 CAPSTONE_HAS_ARM CAPSTONE_USE_SYS_DYN_MEM)

file(
    GLOB
    ropf_f
    src/*.cc
    third_party/capstone/arch/X86/*.c
    third_party/capstone/arch/AArch64/*.c
    third_party/capstone/arch/ARM/*.c
    third_party/capstone/*.c
)

add_executable(ropf ${ropf_f})
target_include_directories(ropf PUBLIC
                           "${PROJECT_BINARY_DIR}"
                           )
