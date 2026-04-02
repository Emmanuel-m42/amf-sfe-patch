cmake_minimum_required(VERSION 3.10)
project(amf-sfe-patch C)

set(CMAKE_C_STANDARD 11)

# Phase 1: File patcher
add_executable(amf-sfe-patch amf-sfe-patch.c)
if(WIN32)
    target_link_libraries(amf-sfe-patch shlwapi)
endif()

# Phase 2: Runtime memory patcher (Windows only)
if(WIN32)
    add_executable(amf-sfe-launch amf-sfe-launch.c)
    target_link_libraries(amf-sfe-launch psapi)
endif()
