# obserwrt - portable eBPF network observability
#
# One build definition for both targets:
#   - plain Linux / Debian 13 (default): config_mini.cpp + vendored inifile-cpp,
#     CPack DEB optional (-DOBSEWRRT_ENABLE_CPACK=ON)
#   - OpenWrt (via $(INCLUDE_DIR)/cmake.mk): -DOBSEWRRT_USE_LIBUCI=ON
#     -DOBSEWRRT_OS=openwrt -DOBSEWRRT_ARCH=<arch> -DOBSEWRRT_VERSION=<pkgver>
#     (config_luci.cpp lands together with the libuci wiring)
cmake_minimum_required(VERSION 3.20)

# Version tracks PKG_VERSION; the maintainer bumps to 1.0.0 deliberately
# (SemVer stability declaration); this file never auto-bumps.
project(obserwrt
  VERSION 0.2.6
  LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(OBSEWRRT_USE_LIBUCI "Build with the OpenWrt libuci config backend" OFF)
option(OBSEWRRT_ENABLE_CPACK "Enable CPack .deb packaging (plain Linux)" OFF)
option(OBSEWRRT_BUILD_TESTS "Build the golden-vector harness" ON)

# Optimization follows the toolchain preferences. OpenWrt injects the image
# flags via cmake.mk; Linux release defaults to -O2 (x86_64 fleet).
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()
set(CMAKE_CXX_FLAGS_RELEASE "-O2 -DNDEBUG")

# Platform identity for build_info / defaults.
if(OBSEWRRT_USE_LIBUCI)
  set(OBSEWRRT_OS_DEFAULT "openwrt")
  set(OBSEWRRT_DEFAULT_CONFIG "/etc/config/obserwrt")
  set(OBSEWRRT_DEFAULT_BPF_OBJ "/lib/bpf/obserwrt-bpf.o")
else()
  set(OBSEWRRT_OS_DEFAULT "linux")
  set(OBSEWRRT_DEFAULT_CONFIG "/etc/obserwrt.conf")
  set(OBSEWRRT_DEFAULT_BPF_OBJ "/usr/lib/obserwrt/obserwrt-bpf.o")
endif()

set(OBSEWRRT_OS "${OBSEWRRT_OS_DEFAULT}" CACHE STRING "build_info os label")
set(OBSEWRRT_ARCH "${CMAKE_SYSTEM_PROCESSOR}" CACHE STRING "build_info arch label")

# Commit SHA injected at configure time when available; empty otherwise so
# source tarballs (OpenWrt feed updates) still build.
find_package(Git QUIET)
if(GIT_FOUND AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/.git")
  execute_process(
    COMMAND "${GIT_EXECUTABLE}" rev-parse --short HEAD
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
    OUTPUT_VARIABLE OBSEWRRT_COMMIT
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET)
else()
  set(OBSEWRRT_COMMIT "")
endif()

set(OBSEWRRT_CXX_FLAGS -Wall -Wextra -Wpedantic -Werror
    -fno-exceptions -fno-rtti -fno-threadsafe-statics)

# ---------------- core library (shared by daemon + harness) ----------------

# Config backend: libuci on OpenWrt, vendored inifile-cpp on plain Linux.
if(OBSEWRRT_USE_LIBUCI)
  set(OBSEWRRT_CONFIG_SRC src/config_luci.cpp)
else()
  set(OBSEWRRT_CONFIG_SRC src/config_mini.cpp)
endif()

add_library(obserwrt_core OBJECT
  src/bpf.cpp
  src/cli.cpp
  src/exporter_ipfix.cpp
  ${OBSEWRRT_CONFIG_SRC}
  src/exporter_syslog.cpp
  src/lifecycle.cpp
  src/metrics.cpp
  src/prometheus.cpp
  src/reconcile.cpp)

target_include_directories(obserwrt_core PUBLIC src)
# Vendored third-party code (inifile-cpp, nlohmann/json) on the SYSTEM
# include path: compilers and clang-tidy treat it as third-party code.
target_include_directories(obserwrt_core SYSTEM PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/vendor)

# Config backend: libuci is exception-free; inifile-cpp throws so its TU keeps
# -fexceptions contained. libbpf is needed by both targets.
if(OBSEWRRT_USE_LIBUCI)
  # On OpenWrt the staging include comes via cmake.mk's TARGET_CPPFLAGS; for
  # plain host builds (and the release .deb) resolve them explicitly.
  find_path(UCI_INCLUDE_DIR NAMES uci.h)
  if(UCI_INCLUDE_DIR)
    target_include_directories(obserwrt_core PUBLIC ${UCI_INCLUDE_DIR})
  endif()
  find_library(UCI_LIBRARY NAMES uci)
  if(UCI_LIBRARY)
    target_link_libraries(obserwrt_core PUBLIC ${UCI_LIBRARY})
  else()
    target_link_libraries(obserwrt_core PUBLIC uci)
  endif()
else()
  set_source_files_properties(src/config_mini.cpp PROPERTIES
    COMPILE_OPTIONS "-fexceptions")
endif()
target_link_libraries(obserwrt_core PUBLIC bpf)
target_compile_definitions(obserwrt_core PUBLIC
  OBSEWRRT_VERSION="${PROJECT_VERSION}"
  OBSEWRRT_COMMIT="${OBSEWRRT_COMMIT}"
  OBSEWRRT_OS="${OBSEWRRT_OS}"
  OBSEWRRT_ARCH="${OBSEWRRT_ARCH}"
  OBSEWRRT_DEFAULT_CONFIG="${OBSEWRRT_DEFAULT_CONFIG}"
  OBSEWRRT_DEFAULT_BPF_OBJ="${OBSEWRRT_DEFAULT_BPF_OBJ}")
target_compile_options(obserwrt_core PRIVATE ${OBSEWRRT_CXX_FLAGS})
set_target_properties(obserwrt_core PROPERTIES POSITION_INDEPENDENT_CODE ON)

# ---------------- daemon ----------------

add_executable(obserwrt src/main.cpp)
target_link_libraries(obserwrt PRIVATE obserwrt_core)
target_compile_options(obserwrt PRIVATE ${OBSEWRRT_CXX_FLAGS})

install(TARGETS obserwrt RUNTIME DESTINATION bin)

# ---------------- eBPF object (plain-Linux packages) ----------------
# OpenWrt builds the .o via bpf.mk; on Linux the package must contain it at
# the daemon's default path (/usr/lib/obserwrt/obserwrt-bpf.o). Build from
# source with clang (same include shim the CI smoke uses).
if(NOT OBSEWRRT_USE_LIBUCI)
  option(OBSEWRRT_BUILD_BPF "Build obserwrt-bpf.o for the Linux packages" ON)
  if(OBSEWRRT_BUILD_BPF)
    find_program(BPF_CLANG clang)
    if(BPF_CLANG)
      set(BPF_SHIM ${CMAKE_BINARY_DIR}/bpf-uapi)
      set(BPF_OBJECT ${CMAKE_BINARY_DIR}/obserwrt-bpf.o)
      set(BPF_INCS
        -I${BPF_SHIM}
        -I/usr/include
        -target bpfel)
      if(CMAKE_LIBRARY_ARCHITECTURE)
        list(APPEND BPF_INCS -I/usr/include/${CMAKE_LIBRARY_ARCHITECTURE})
      endif()
      add_custom_command(OUTPUT ${BPF_OBJECT}
        COMMAND ${CMAKE_COMMAND} -E make_directory ${BPF_SHIM}/uapi
        COMMAND ${CMAKE_COMMAND} -E create_symlink /usr/include/linux
          ${BPF_SHIM}/uapi/linux
        COMMAND ${BPF_CLANG} -O2 -g ${BPF_INCS}
          -c ${CMAKE_CURRENT_SOURCE_DIR}/obserwrt/src/obserwrt-bpf.c
          -o ${BPF_OBJECT}
        DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/obserwrt/src/obserwrt-bpf.c
        COMMENT "Building obserwrt-bpf.o")
      add_custom_target(obserwrt_bpf_o ALL DEPENDS ${BPF_OBJECT})
      install(FILES ${BPF_OBJECT} DESTINATION lib/obserwrt)
    else()
      message(WARNING "clang not found; obserwrt-bpf.o will not be built")
    endif()
  endif()
endif()

# Plain-Linux visibility: config sample + systemd unit (OpenWrt installs the
# UCI config + procd init from obserwrt/files/ via its own Makefile).
if(NOT OBSEWRRT_USE_LIBUCI)
  install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/linux/obserwrt.conf DESTINATION /etc)
  install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/linux/obserwrt.service
    DESTINATION /lib/systemd/system)
endif()

# ---------------- tests ----------------

if(OBSEWRRT_BUILD_TESTS)
  enable_testing()
  add_executable(obserwrt-harness tests/harness.cpp)
  target_link_libraries(obserwrt-harness PRIVATE obserwrt_core)
  target_compile_options(obserwrt-harness PRIVATE ${OBSEWRRT_CXX_FLAGS})
  add_test(NAME golden-vectors COMMAND obserwrt-harness)
endif()

# ---------------- CPack (.deb, Debian 13 / amd64) ----------------

if(OBSEWRRT_ENABLE_CPACK)
  # Canonical /usr tree for the .deb (host cmake defaults to /usr/local).
  set(CMAKE_INSTALL_PREFIX "/usr" CACHE STRING "Install path prefix" FORCE)
  set(CPACK_GENERATOR DEB)
  set(CPACK_DEBIAN_PACKAGE_ARCHITECTURE "amd64")
  set(CPACK_PACKAGE_FILE_NAME "obserwrt_${PROJECT_VERSION}_amd64")
  set(CPACK_PACKAGE_NAME obserwrt)
  set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")
  set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "eBPF network observability agent")
  set(CPACK_DEBIAN_PACKAGE_MAINTAINER
    "Vladimir Ermakov <vooon341@gmail.com>")
  set(CPACK_DEBIAN_PACKAGE_DEPENDS "libbpf1 (>= 1.4), libstdc++6 (>= 12)")
  set(CPACK_DEBIAN_PACKAGE_SECTION net)
  include(CPack)
endif()
