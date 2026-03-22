// Copyright (c) 2026
// SPDX-License-Identifier: MIT
//
// dl_interceptor - Monitor ELF .init/.init_array and .fini/.fini_array execution
//
// Hooks soinfo::call_constructors() and soinfo::call_destructors() in the Android
// linker to provide callbacks before and after ELF initialization/finalization.
//
// Supports: Android 5.0+ (API 21+), armeabi-v7a, arm64-v8a, x86, x86_64
// Dependencies: DobbyHook (inline hooking), xDL (symbol resolution)

#pragma once

#include <link.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Callback type: receives dl_phdr_info for the ELF being initialized/finalized.
//   info  - ELF program header info (dlpi_addr, dlpi_name, dlpi_phdr, dlpi_phnum)
//   size  - size of the dl_phdr_info struct
//   data  - user-provided opaque pointer from registration
typedef void (*dl_interceptor_callback_t)(struct dl_phdr_info *info, size_t size, void *data);

// Initialize dl_interceptor. Must be called before registering callbacks.
// Returns 0 on success, -1 on failure.
// Can be called multiple times safely (only initializes once).
int dl_interceptor_init(void);

// Register callbacks for ELF .init + .init_array execution.
//   pre  - called AFTER ELF is mapped+relocated, BEFORE .init/.init_array runs (may be NULL)
//   post - called AFTER .init/.init_array finishes (may be NULL)
//   data - opaque pointer passed back to callbacks
// Returns 0 on success, -1 on failure.
int dl_interceptor_register_dl_init_callback(dl_interceptor_callback_t pre,
                                             dl_interceptor_callback_t post, void *data);

// Unregister a previously registered dl_init callback.
// Pass the same pre, post, data used during registration.
// Returns 0 on success, -1 if not found.
int dl_interceptor_unregister_dl_init_callback(dl_interceptor_callback_t pre,
                                               dl_interceptor_callback_t post, void *data);

// Register callbacks for ELF .fini + .fini_array execution.
//   pre  - called BEFORE .fini/.fini_array runs (may be NULL)
//   post - called AFTER .fini/.fini_array finishes (may be NULL)
//   data - opaque pointer passed back to callbacks
// Returns 0 on success, -1 on failure.
int dl_interceptor_register_dl_fini_callback(dl_interceptor_callback_t pre,
                                             dl_interceptor_callback_t post, void *data);

// Unregister a previously registered dl_fini callback.
// Returns 0 on success, -1 if not found.
int dl_interceptor_unregister_dl_fini_callback(dl_interceptor_callback_t pre,
                                               dl_interceptor_callback_t post, void *data);

#ifdef __cplusplus
}
#endif
