# Intel(R) Silicon Security Engine Interface Library

ISSEI Library is a C library to access Intel(R) Silicon Security Engine firmware via
a Intel(R) Silicon Security Engine Interface.
ISSEI Library provides a single cross-platform API to access to ISSEI devices on Linux and Windows.

## Build prerequisites

### Cross-platform

#### GoogleTest (only for builds with tests enabled)

For builds that includes tests CMake script search for googltest and
downloads googletest from [GitHub](https://github.com/google/googletest) if not found locally.

## CMake Build

ISSEI library uses CMake for both Linux and Windows builds.

### Windows

From the "Developer Command Prompt for VS 2019" with C compiler and CMake component installed:

1. Go to sources directory: `cd <srcdir>`
2. Create `build` directory: `mkdir build`
3. Run `cmake -G "Visual Studio 16 2019" -A <Build_arch> <srcdir>` from the `build` directory (best to set *build_arch* to x64)
4. Run `cmake --build . --config Release --target package -j <nproc>` from the `build` directory to build an archive with all executables and libraries, *nproc* is the number of parallel threads in compilation, best to set to number of processor threads available

By default CMake links with dynamic runtime (/MD), set BUILD_MSVC_RUNTIME_STATIC to ON to link with static runtime (/MT):
`cmake -G "Visual Studio 16 2019" -A <Build_arch> -DBUILD_MSVC_RUNTIME_STATIC=ON <srcdir>`

### Linux

1. Create `build` directory
2. Run `cmake <srcdir>` from the `build` directory
3. Run `make -j$(nproc) package` from the `build` directory to build .deb and .rpm packages and .tgz archive

## Thread safety

The library supports multithreading but is not thread-safe.
Every thread should either initialize and use its own handle
or a locking mechanism should be implemented by the caller to ensure
that only one thread uses the handle at any time.
The only exception is ability to call disconnect to exit from read
blocked on another thread.
