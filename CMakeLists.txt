cmake_minimum_required(VERSION 3.22.1)
project(dl_interceptor LANGUAGES C CXX)

# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------
option(DI_BUILD_SHARED "Build dl_interceptor as shared library (.so)" OFF)
option(DI_BUILD_NOTHING "Build the dummy scanning library" ON)
option(DI_USE_ASAN "Enable AddressSanitizer" OFF)

# ---------------------------------------------------------------------------
# xDL (static library)
# ---------------------------------------------------------------------------
add_subdirectory(third_party/xdl)

# ---------------------------------------------------------------------------
# dl_interceptor
# ---------------------------------------------------------------------------
set(DI_SOURCES src/dl_interceptor.cpp)

if(DI_BUILD_SHARED)
    add_library(dl_interceptor SHARED ${DI_SOURCES})
else()
    add_library(dl_interceptor STATIC ${DI_SOURCES})
endif()

target_compile_features(dl_interceptor PUBLIC cxx_std_17)
target_include_directories(dl_interceptor
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(dl_interceptor
    PUBLIC  log
    PRIVATE xdl
)

# Compiler flags
target_compile_options(dl_interceptor PRIVATE
    -Wall -Wextra -Werror
    -Wno-unused-parameter
    -fvisibility=hidden
)

if(DI_USE_ASAN)
    target_compile_options(dl_interceptor PRIVATE -fsanitize=address -fno-omit-frame-pointer)
    target_link_options(dl_interceptor PRIVATE -fsanitize=address)
else()
    target_compile_options(dl_interceptor PRIVATE -Os -ffunction-sections -fdata-sections)
    target_link_options(dl_interceptor PRIVATE -Wl,--gc-sections)
endif()

# 16KB page size alignment for arm64 / x86_64
if((${ANDROID_ABI} STREQUAL "arm64-v8a") OR (${ANDROID_ABI} STREQUAL "x86_64"))
    target_link_options(dl_interceptor PRIVATE "-Wl,-z,max-page-size=16384")
endif()

# ---------------------------------------------------------------------------
# libdl_interceptor_nothing.so (dummy library for soinfo scanning)
# ---------------------------------------------------------------------------
if(DI_BUILD_NOTHING)
    add_library(dl_interceptor_nothing SHARED nothing/dl_interceptor_nothing.c)
    target_compile_options(dl_interceptor_nothing PRIVATE
        -Oz -fno-ident -fno-unwind-tables -fno-asynchronous-unwind-tables
    )
    target_link_options(dl_interceptor_nothing PRIVATE
        -Wl,--strip-all -Wl,--as-needed -Wl,--build-id=none
        -nostartfiles -nodefaultlibs
    )
    if((${ANDROID_ABI} STREQUAL "arm64-v8a") OR (${ANDROID_ABI} STREQUAL "x86_64"))
        target_link_options(dl_interceptor_nothing PRIVATE "-Wl,-z,max-page-size=16384")
    endif()
endif()
