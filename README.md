<h1 align="center">Turbo ASAR</h1>

<p align="center">
  <b>⚡ High-performance ASAR archive library written in C</b>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#performance">Performance</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#api">API</a> •
  <a href="#building">Building</a>
</p>

---

A blazing-fast, minimal C implementation for creating and extracting ASAR archives. Fully compatible with Electron's ASAR format.

## Features

- **Zero Dependency** - Minimalist design for speed and portability
- **Cross-Platform** - Linux, macOS, and Windows support
- **Native C Implementation** - No JavaScript/Node.js overhead
- **Extremely Fast** - Hardware-accelerated SHA256 (SHA-NI on x86, ARMv8 crypto on ARM64)
- **Memory Efficient** -Memory-mapped file I/O for large files (using mmap for files > 4MB)
- **Sequential Read Hints** - `posix_fadvise` and `madvise` for optimal caching
- **Block-Based Hashing** - Efficient incremental hashing for integrity verification
- **Full ASAR Support** - Pack, extract, list, and stat operations
- **Symlink Support** - Full symlink preservation on Unix


## Performance

### turbo-asar vs @electron/asar (CLI Comparison)

#### Small Archives (10 files, ~50KB)

| Operation | @electron/asar | turbo-asar | Speedup        |
|-----------|----------------|------------|----------------|
| pack      | 99 ms          | 2.1 ms     | **46x faster** |
| extract   | 69 ms          | 2.7 ms     | **25x faster** |
| list      | 68 ms          | 1.9 ms     | **37x faster** |

#### Medium Archives (100 files, ~10MB)

| Operation | @electron/asar | turbo-asar | Speedup         |
|-----------|----------------|------------|-----------------|
| pack      | 247 ms         | 27 ms      | **9x faster**   |
| extract   | 96 ms          | 18 ms      | **5.5x faster** |
| list      | 71 ms          | 2.0 ms     | **36x faster**  |

#### Large Archives (1000 files, ~100MB)

| Operation | @electron/asar | turbo-asar | Speedup         |
|-----------|----------------|------------|-----------------|
| pack      | 736 ms         | 262 ms     | **2.8x faster** |
| extract   | 297 ms         | 186 ms     | **1.6x faster** |
| list      | 92 ms          | 5.6 ms     | **16x faster**  |

*Benchmarked on Linux x64 with Node.js v20. turbo-asar uses native C with hardware-accelerated SHA256.*

## Installation

### From Source

```bash
git clone https://github.com/k1tbyte/turbo-asar.git
cd turbo-asar
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -DENABLE_NATIVE_ARCH=ON
make -j$(nproc)
sudo make install
```

### Options

| Option | Default | Description |
|--------|---------|-------------|
| `ENABLE_NATIVE_ARCH` | ON | Enable CPU-specific optimizations |
| `BUILD_SHARED_LIBS` | OFF | Build shared library instead of static |
| `BUILD_CLI` | ON | Build command-line tool |
| `BUILD_TESTS` | ON | Build test suite |
| `BUILD_BENCHMARKS` | ON | Build benchmarks |

## Usage

### Command Line

```bash
# Create an archive
turbo-asar pack ./my-app app.asar

# Extract an archive
turbo-asar extract app.asar ./output

# List contents
turbo-asar list app.asar

# Extract single file
turbo-asar extract-file app.asar path/to/file.js output.js

# Options
turbo-asar pack ./my-app app.asar --no-integrity     # Skip integrity hashes
turbo-asar pack ./my-app app.asar --exclude-hidden   # Skip hidden files
```

### C Library

```c
#include <turbo_asar.h>

int main() {
    // Pack a directory
    turbo_asar_pack_options_t options = {0};
    options.calculate_integrity = true;
    
    turbo_asar_error_t err = turbo_asar_pack("./my-app", "app.asar", &options);
    if (err != TURBO_ASAR_OK) {
        printf("Error: %s\n", turbo_asar_strerror(err));
        return 1;
    }
    
    // Extract entire archive
    err = turbo_asar_extract_all("app.asar", "./output");
    
    // Extract single file
    uint8_t *buffer;
    size_t size;
    err = turbo_asar_extract_file("app.asar", "main.js", &buffer, &size);
    // ... use buffer ...
    free(buffer);
    
    // List files
    char **files;
    size_t count;
    err = turbo_asar_list("app.asar", &files, &count);
    for (size_t i = 0; i < count; i++) {
        printf("%s\n", files[i]);
    }
    turbo_asar_free_list(files, count);
    
    return 0;
}
```

## API

### Core Functions

| Function | Description                        |
|----------|------------------------------------|
| `turbo_asar_pack()` | Create ASAR archive from directory |
| `turbo_asar_extract_all()` | Extract entire archive             |
| `turbo_asar_extract_file()` | Extract single file to buffer      |
| `turbo_asar_list()` | List all files in archive          |
| `turbo_asar_stat()` | Get file metadata                  |
| `turbo_asar_get_header()` | Get raw JSON header                |
| `turbo_asar_version()` | Get library version                |
| `turbo_asar_strerror()` | Get error message                  |

## Building

### Prerequisites

- CMake 3.16+
- C11 compiler (GCC, Clang, MSVC)

### Build Commands

```bash
# Debug build
cmake .. -DCMAKE_BUILD_TYPE=Debug
make

# Release build with native optimizations
cmake .. -DCMAKE_BUILD_TYPE=Release -DENABLE_NATIVE_ARCH=ON
make

# Run tests
./test_sha256
./test_pickle
./test_asar

# Run benchmarks
./benchmark_asar
./benchmark_sha256  # Requires OpenSSL

# Run comparison benchmark against @electron/asar
cd benchmarks/electron-comparison
npm install
node benchmark.js
```

## ASAR Format Compatibility

Turbo ASAR is fully compatible with Electron's ASAR format:

- ✅ Standard ASAR header format (Pickle serialization)
- ✅ File integrity hashes (SHA256)
- ✅ Block-level integrity (4MB blocks)
- ✅ Unpacked files support with glob pattern
- ✅ Symlink preservation
- ✅ Executable bit preservation

## License

Apache-2.0 - see the [LICENSE](LICENSE.txt) file for details

## Credits

- **ASAR**: Based on [Electron's ASAR](https://github.com/electron/asar) implementation
- **JSON**: Uses [cJSON](https://github.com/DaveGamble/cJSON) for header parsing
- **Glob**: Pattern matching based on [Linux kernel implementation](https://github.com/torvalds/linux/blob/master/lib/glob.c)