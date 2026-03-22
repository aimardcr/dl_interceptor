# dl_interceptor

An Android native library that monitors ELF `.init` / `.init_array` and `.fini` / `.fini_array` execution by hooking the linker's `soinfo::call_constructors()` and `soinfo::call_destructors()`.

Provides **pre** and **post** callbacks around constructor/destructor execution — letting you act on a library **after** it's mapped and relocated but **before** its initialization code runs.

## Features

- Callbacks fire before and after `.init` + `.init_array` (and `.fini` + `.fini_array`)
- Supports **armeabi-v7a**, **arm64-v8a**, **x86**, and **x86_64**
- Supports Android 5.0 - 16 (API 21 - 36)
- Runtime `soinfo` struct scanning — no hardcoded offsets, works across AOSP and vendor-modified linkers (Samsung, Xiaomi, Huawei, etc.)
- Self-contained inline hook (`mini_hook.hpp`) — no dependency on Dobby, Substrate, or ShadowHook
- Only dependency: [xDL](https://github.com/nicksym/xDL) for symbol resolution
- Can be built as static library (`.a`), shared library (`.so`), or included directly as source

## How It Works

1. Uses **xDL** to find `soinfo::call_constructors()` and `soinfo::call_destructors()` symbols in the linker binary
2. Installs a minimal **inline hook** at both function entry points via `mini_hook.hpp`
3. Loads a tiny dummy `.so` (`libdl_interceptor_nothing.so`) to trigger `call_constructors()`, then **scans the `soinfo` struct memory** to discover field offsets at runtime
4. On every subsequent `dlopen()`, the hooked `call_constructors()` converts the raw `soinfo*` into a `dl_phdr_info` and invokes registered user callbacks

## Callback Timing

```
dlopen("libfoo.so")
│
├── Linker maps ELF into memory
├── Linker resolves relocations (fills GOT/PLT)
│
├── >>> PRE callback fires here <<<
│
├── Linker runs .init
├── Linker runs .init_array
│
├── >>> POST callback fires here <<<
│
└── dlopen() returns
```

## Integration

### As a CMake subdirectory

```cmake
add_subdirectory(dl_interceptor)
target_link_libraries(your_lib PRIVATE dl_interceptor)
```

This produces `libdl_interceptor.a` (static, default) and `libdl_interceptor_nothing.so` (dummy lib).

To build as shared library instead:

```cmake
set(DI_BUILD_SHARED ON)
add_subdirectory(dl_interceptor)
```

### As source code

Copy `include/dl_interceptor.h`, `src/dl_interceptor.cpp`, and `src/mini_hook.hpp` into your project. Ensure xDL headers and source are in your include/build path.

### Dummy library

`libdl_interceptor_nothing.so` **must** be present in your APK's `lib/<abi>/` folder. Prebuilt binaries for all 4 ABIs are in `nothing/libs/`. If you use the CMake integration, it's built automatically.

## API

```c
#include "dl_interceptor.h"

// Initialize (call once, before registering callbacks)
int dl_interceptor_init(void);

// Callback type
typedef void (*dl_interceptor_callback_t)(struct dl_phdr_info *info, size_t size, void *data);

// Register/unregister .init callbacks
int dl_interceptor_register_dl_init_callback(
    dl_interceptor_callback_t pre,   // called before .init/.init_array (may be NULL)
    dl_interceptor_callback_t post,  // called after .init/.init_array (may be NULL)
    void *data);                     // opaque pointer passed to callbacks

int dl_interceptor_unregister_dl_init_callback(
    dl_interceptor_callback_t pre,
    dl_interceptor_callback_t post,
    void *data);

// Register/unregister .fini callbacks
int dl_interceptor_register_dl_fini_callback(
    dl_interceptor_callback_t pre,
    dl_interceptor_callback_t post,
    void *data);

int dl_interceptor_unregister_dl_fini_callback(
    dl_interceptor_callback_t pre,
    dl_interceptor_callback_t post,
    void *data);
```

## Example

```cpp
#include "dl_interceptor.h"
#include <android/log.h>

void on_lib_pre_init(struct dl_phdr_info *info, size_t size, void *data) {
    __android_log_print(ANDROID_LOG_INFO, "MyApp",
        "Library loading: %s (base=0x%lx)", info->dlpi_name, info->dlpi_addr);
}

void on_lib_post_init(struct dl_phdr_info *info, size_t size, void *data) {
    __android_log_print(ANDROID_LOG_INFO, "MyApp",
        "Library loaded: %s", info->dlpi_name);
}

void setup() {
    dl_interceptor_init();
    dl_interceptor_register_dl_init_callback(on_lib_pre_init, on_lib_post_init, nullptr);
}
```

## Project Structure

```
dl_interceptor/
├── CMakeLists.txt                 # Build configuration
├── include/
│   └── dl_interceptor.h          # Public C API
├── src/
│   ├── dl_interceptor.cpp        # Core implementation
│   └── mini_hook.hpp             # Header-only inline hook (ARM32/64, x86/64)
├── nothing/
│   ├── dl_interceptor_nothing.c  # Dummy .so source
│   ├── jni/                      # NDK build files for the dummy .so
│   │   ├── Android.mk
│   │   └── Application.mk
│   └── libs/                     # Prebuilt dummy .so for all ABIs
│       ├── arm64-v8a/
│       ├── armeabi-v7a/
│       ├── x86/
│       └── x86_64/
└── third_party/
    └── xdl/                      # Symbol resolution library
```

## Requirements

- Android NDK (API 21+)
- C++17

## License

MIT
