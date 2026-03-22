// Copyright (c) 2026
// SPDX-License-Identifier: MIT
//
// dl_interceptor - Monitor ELF .init/.init_array and .fini/.fini_array execution
//
// Implementation: hooks soinfo::call_constructors() and soinfo::call_destructors()
// in the Android linker via DobbyHook. Uses xDL for symbol resolution and runtime
// memory scanning to discover soinfo struct field offsets (vendor-independent).

#include "dl_interceptor.h"

#include <android/api-level.h>
#include <android/log.h>
#include <dlfcn.h>
#include <elf.h>
#include <inttypes.h>
#include <link.h>
#include <atomic>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/system_properties.h>
#include <unistd.h>

#include "mini_hook.hpp"
#include "xdl.h"

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------

#define DI_TAG "DLInterceptor"
#define DI_LOGI(...) __android_log_print(ANDROID_LOG_INFO, DI_TAG, __VA_ARGS__)
#define DI_LOGW(...) __android_log_print(ANDROID_LOG_WARN, DI_TAG, __VA_ARGS__)
#define DI_LOGE(...) __android_log_print(ANDROID_LOG_ERROR, DI_TAG, __VA_ARGS__)

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

#ifndef __LP64__
#define DI_LINKER_BASENAME "linker"
#else
#define DI_LINKER_BASENAME "linker64"
#endif

// The dummy .so used for soinfo memory scanning.
// This must be a real .so that can be dlopen'd. It can be an empty library
// from your project — just needs to exist in the APK's lib/<abi>/ folder.
// If you don't have one, create a .so with a single unused symbol.
#ifndef DI_DUMMY_LIB_NAME
#define DI_DUMMY_LIB_NAME "libdl_interceptor_nothing.so"
#endif

// Symbol names for soinfo::call_constructors / call_destructors
// Android L (5.0-5.1): CamelCase
#define DI_SYM_CALL_CTORS_L "__dl__ZN6soinfo16CallConstructorsEv"
#define DI_SYM_CALL_DTORS_L "__dl__ZN6soinfo15CallDestructorsEv"
// Android M+ (6.0+): snake_case
#define DI_SYM_CALL_CTORS_M "__dl__ZN6soinfo17call_constructorsEv"
#define DI_SYM_CALL_DTORS_M "__dl__ZN6soinfo16call_destructorsEv"

// Max scan depth for soinfo struct (in pointer-sized words)
#define DI_SOINFO_SCAN_WORDS 128

// ---------------------------------------------------------------------------
// Callback list (intrusive singly-linked list with rwlock)
// ---------------------------------------------------------------------------

struct di_callback {
    dl_interceptor_callback_t pre;
    dl_interceptor_callback_t post;
    void *data;
    di_callback *next;
};

struct di_callback_list {
    di_callback *head;
    pthread_rwlock_t lock;
};

static void di_cb_list_init(di_callback_list *list) {
    list->head = nullptr;
    pthread_rwlock_init(&list->lock, nullptr);
}

static int di_cb_list_add(di_callback_list *list, dl_interceptor_callback_t pre,
                          dl_interceptor_callback_t post, void *data) {
    auto *cb = static_cast<di_callback *>(malloc(sizeof(di_callback)));
    if (!cb) return -1;
    cb->pre = pre;
    cb->post = post;
    cb->data = data;

    pthread_rwlock_wrlock(&list->lock);

    // Check for duplicates
    for (di_callback *cur = list->head; cur; cur = cur->next) {
        if (cur->pre == pre && cur->post == post && cur->data == data) {
            pthread_rwlock_unlock(&list->lock);
            free(cb);
            return -1;  // duplicate
        }
    }

    cb->next = list->head;
    list->head = cb;
    pthread_rwlock_unlock(&list->lock);
    return 0;
}

static int di_cb_list_remove(di_callback_list *list, dl_interceptor_callback_t pre,
                             dl_interceptor_callback_t post, void *data) {
    pthread_rwlock_wrlock(&list->lock);

    di_callback **pp = &list->head;
    while (*pp) {
        di_callback *cur = *pp;
        if (cur->pre == pre && cur->post == post && cur->data == data) {
            *pp = cur->next;
            pthread_rwlock_unlock(&list->lock);
            free(cur);
            return 0;
        }
        pp = &cur->next;
    }

    pthread_rwlock_unlock(&list->lock);
    return -1;  // not found
}

static void di_cb_list_invoke_pre(di_callback_list *list, struct dl_phdr_info *info, size_t size) {
    pthread_rwlock_rdlock(&list->lock);
    for (di_callback *cur = list->head; cur; cur = cur->next) {
        if (cur->pre) cur->pre(info, size, cur->data);
    }
    pthread_rwlock_unlock(&list->lock);
}

static void di_cb_list_invoke_post(di_callback_list *list, struct dl_phdr_info *info, size_t size) {
    pthread_rwlock_rdlock(&list->lock);
    for (di_callback *cur = list->head; cur; cur = cur->next) {
        if (cur->post) cur->post(info, size, cur->data);
    }
    pthread_rwlock_unlock(&list->lock);
}

// ---------------------------------------------------------------------------
// Global state
// ---------------------------------------------------------------------------

static di_callback_list g_init_cbs;
static di_callback_list g_fini_cbs;

// soinfo field offsets discovered at runtime
static size_t g_off_load_bias = SIZE_MAX;
static size_t g_off_name = SIZE_MAX;
static size_t g_off_phdr = SIZE_MAX;
static size_t g_off_phnum = SIZE_MAX;
static size_t g_off_constructors_called = SIZE_MAX;

static std::atomic<bool> g_offsets_ready{false};
static std::atomic<pid_t> g_scan_tid{0};

// Original function pointers (set by DobbyHook)
static void (*g_orig_call_constructors)(void *soinfo) = nullptr;
static void (*g_orig_call_destructors)(void *soinfo) = nullptr;

// ---------------------------------------------------------------------------
// API level helper
// ---------------------------------------------------------------------------

static int di_get_api_level() {
    static int level = -1;
    if (level >= 0) return level;
    level = android_get_device_api_level();
    if (level < 0) {
        // Fallback: read from build.prop
        char buf[16] = {};
        __system_property_get("ro.build.version.sdk", buf);
        level = atoi(buf);
    }
    if (level < __ANDROID_API_L__) level = __ANDROID_API_L__;
    return level;
}

// ---------------------------------------------------------------------------
// soinfo → dl_phdr_info conversion
// ---------------------------------------------------------------------------

static bool di_soinfo_is_loading(void *soinfo) {
    auto val = *reinterpret_cast<uint8_t *>(reinterpret_cast<uintptr_t>(soinfo) + g_off_constructors_called);
    return val == 0;
}

static void di_soinfo_to_dlinfo(void *soinfo, struct dl_phdr_info *info) {
    auto base = reinterpret_cast<uintptr_t>(soinfo);
    info->dlpi_addr = *reinterpret_cast<ElfW(Addr) *>(base + g_off_load_bias);
    info->dlpi_name = *reinterpret_cast<const char **>(base + g_off_name);
    info->dlpi_phdr = *reinterpret_cast<const ElfW(Phdr) **>(base + g_off_phdr);
    info->dlpi_phnum = static_cast<ElfW(Half)>(*reinterpret_cast<size_t *>(base + g_off_phnum));
}

// ---------------------------------------------------------------------------
// soinfo memory scanning — discover field offsets at runtime
// ---------------------------------------------------------------------------

static int di_soinfo_scan_pre(void *soinfo) {
    // Open the dummy lib via xDL to get its known values
    void *handle = xdl_open(DI_DUMMY_LIB_NAME, XDL_DEFAULT);
    if (!handle) {
        DI_LOGE("scan: xdl_open(%s) failed", DI_DUMMY_LIB_NAME);
        return -1;
    }

    xdl_info_t dlinfo;
    xdl_info(handle, XDL_DI_DLINFO, &dlinfo);

    // Find PT_DYNAMIC vaddr
    uintptr_t l_ld = UINTPTR_MAX;
    for (size_t i = 0; i < dlinfo.dlpi_phnum; i++) {
        if (dlinfo.dlpi_phdr[i].p_type == PT_DYNAMIC) {
            l_ld = reinterpret_cast<uintptr_t>(dlinfo.dli_fbase) + dlinfo.dlpi_phdr[i].p_vaddr;
            break;
        }
    }
    if (l_ld == UINTPTR_MAX) {
        DI_LOGE("scan: PT_DYNAMIC not found in %s", DI_DUMMY_LIB_NAME);
        xdl_close(handle);
        return -1;
    }

    auto si = reinterpret_cast<uintptr_t>(soinfo);
    auto known_phdr = reinterpret_cast<uintptr_t>(dlinfo.dlpi_phdr);
    auto known_phnum = static_cast<uintptr_t>(dlinfo.dlpi_phnum);
    auto known_load_bias = reinterpret_cast<uintptr_t>(dlinfo.dli_fbase);

    // Scan soinfo memory for known patterns
    for (size_t i = 0; i < sizeof(uintptr_t) * DI_SOINFO_SCAN_WORDS; i += sizeof(uintptr_t)) {
        if (g_off_phdr != SIZE_MAX && g_off_load_bias != SIZE_MAX)
            break;  // found everything

        uintptr_t v0 = *reinterpret_cast<uintptr_t *>(si + i);
        uintptr_t v1 = *reinterpret_cast<uintptr_t *>(si + i + sizeof(uintptr_t));
        uintptr_t v2 = *reinterpret_cast<uintptr_t *>(si + i + sizeof(uintptr_t) * 2);
        uintptr_t v5 = *reinterpret_cast<uintptr_t *>(si + i + sizeof(uintptr_t) * 5);
        uintptr_t v6 = *reinterpret_cast<uintptr_t *>(si + i + sizeof(uintptr_t) * 6);

        // Pattern 1: phdr, phnum adjacent
        if (g_off_phdr == SIZE_MAX && v0 == known_phdr && v1 == known_phnum) {
            g_off_phdr = i;
            g_off_phnum = i + sizeof(uintptr_t);
            i += sizeof(uintptr_t);
            continue;
        }

        // Pattern 2: link_map layout: load_bias, l_name, l_ld, l_next, l_prev(0), load_bias_again
        // Matches: load_bias == dli_fbase, l_ld == PT_DYNAMIC addr, l_prev == 0, load_bias field == load_bias
        if (g_off_load_bias == SIZE_MAX && v0 == known_load_bias && v2 == l_ld && v5 == 0 &&
            v6 == known_load_bias) {
            // Verify l_name points to a string ending with our dummy lib name
            auto l_name = reinterpret_cast<const char *>(v1);
            size_t dummy_len = strlen(DI_DUMMY_LIB_NAME);
            size_t name_len = strlen(l_name);
            if (name_len >= dummy_len &&
                strcmp(l_name + name_len - dummy_len, DI_DUMMY_LIB_NAME) == 0) {
                g_off_load_bias = i;
                g_off_name = i + sizeof(uintptr_t);
                // constructors_called is at a known offset from the link_map fields
                // In AOSP: link_map { l_addr, l_name, l_ld, l_next, l_prev } then constructors_called
                g_off_constructors_called = i + sizeof(uintptr_t) * 5;
                i += sizeof(uintptr_t) * 6;
                continue;
            }
        }
    }

    xdl_close(handle);

    if (g_off_load_bias == SIZE_MAX || g_off_name == SIZE_MAX || g_off_phdr == SIZE_MAX ||
        g_off_phnum == SIZE_MAX || g_off_constructors_called == SIZE_MAX) {
        DI_LOGE("scan: failed to discover offsets (load_bias=%zu, name=%zu, phdr=%zu, phnum=%zu, called=%zu)",
                g_off_load_bias, g_off_name, g_off_phdr, g_off_phnum, g_off_constructors_called);
        return -1;
    }

    DI_LOGI("scan: offsets discovered (load_bias=%zu, name=%zu, phdr=%zu, phnum=%zu, called=%zu)",
            g_off_load_bias, g_off_name, g_off_phdr, g_off_phnum, g_off_constructors_called);
    return 0;
}

static void di_soinfo_scan_post(void *soinfo) {
    auto val = *reinterpret_cast<uintptr_t *>(reinterpret_cast<uintptr_t>(soinfo) + g_off_constructors_called);
    if (val != 0) {
        g_offsets_ready.store(true, std::memory_order_release);
        DI_LOGI("scan: post-verification OK, offsets confirmed");
    } else {
        DI_LOGE("scan: post-verification FAILED, constructors_called still 0");
    }
}

// ---------------------------------------------------------------------------
// Proxy functions for soinfo::call_constructors / call_destructors
// ---------------------------------------------------------------------------

static void proxy_call_constructors(void *soinfo) {
    pid_t scan_tid = g_scan_tid.load(std::memory_order_acquire);

    if (scan_tid == 0) {
        // Normal path: offsets are ready, invoke user callbacks
        if (g_offsets_ready.load(std::memory_order_relaxed)) {
            if (di_soinfo_is_loading(soinfo)) {
                struct dl_phdr_info info = {};
                di_soinfo_to_dlinfo(soinfo, &info);
                DI_LOGI("ctors: pre  [%s] load_bias=%" PRIxPTR, info.dlpi_name, (uintptr_t)info.dlpi_addr);
                di_cb_list_invoke_pre(&g_init_cbs, &info, sizeof(info));

                g_orig_call_constructors(soinfo);

                DI_LOGI("ctors: post [%s]", info.dlpi_name);
                di_cb_list_invoke_post(&g_init_cbs, &info, sizeof(info));
                return;
            }
        }
    } else if (gettid() == scan_tid) {
        // Scanning path: this is our dummy .so being loaded
        bool scan_ok = (di_soinfo_scan_pre(soinfo) == 0);

        g_orig_call_constructors(soinfo);

        if (scan_ok) {
            di_soinfo_scan_post(soinfo);
        }
        return;
    }

    // Fallback: just call original
    g_orig_call_constructors(soinfo);
}

static void proxy_call_destructors(void *soinfo) {
    if (g_offsets_ready.load(std::memory_order_relaxed) &&
        g_scan_tid.load(std::memory_order_acquire) == 0) {
        auto val =
            *reinterpret_cast<uint8_t *>(reinterpret_cast<uintptr_t>(soinfo) + g_off_constructors_called);
        if (val != 0) {
            struct dl_phdr_info info = {};
            di_soinfo_to_dlinfo(soinfo, &info);

            // Ignore: call_destructors() during failed load (constructors_called == 0, name/addr == 0)
            if (info.dlpi_addr != 0 && info.dlpi_name != nullptr) {
                DI_LOGI("dtors: pre  [%s]", info.dlpi_name);
                di_cb_list_invoke_pre(&g_fini_cbs, &info, sizeof(info));

                g_orig_call_destructors(soinfo);

                DI_LOGI("dtors: post [%s]", info.dlpi_name);
                di_cb_list_invoke_post(&g_fini_cbs, &info, sizeof(info));
                return;
            }
        }
    }

    g_orig_call_destructors(soinfo);
}

// ---------------------------------------------------------------------------
// Initialization
// ---------------------------------------------------------------------------

static int di_hook_linker() {
    int api = di_get_api_level();

    // Open linker via xDL (bypasses namespace restrictions)
    void *linker = xdl_open(DI_LINKER_BASENAME, XDL_DEFAULT);
    if (!linker) {
        DI_LOGE("hook: xdl_open(%s) failed", DI_LINKER_BASENAME);
        return -1;
    }

    // Resolve soinfo::call_constructors
    const char *ctors_sym = (api >= __ANDROID_API_M__) ? DI_SYM_CALL_CTORS_M : DI_SYM_CALL_CTORS_L;
    void *ctors_addr = xdl_dsym(linker, ctors_sym, nullptr);

    // Resolve soinfo::call_destructors
    const char *dtors_sym = (api >= __ANDROID_API_M__) ? DI_SYM_CALL_DTORS_M : DI_SYM_CALL_DTORS_L;
    void *dtors_addr = xdl_dsym(linker, dtors_sym, nullptr);

    xdl_close(linker);

    if (!ctors_addr || !dtors_addr) {
        DI_LOGE("hook: symbol resolution failed (ctors=%p [%s], dtors=%p [%s])",
                ctors_addr, ctors_sym, dtors_addr, dtors_sym);
        return -1;
    }
    DI_LOGI("hook: resolved %s @ %p", ctors_sym, ctors_addr);
    DI_LOGI("hook: resolved %s @ %p", dtors_sym, dtors_addr);

    // Hook with mini_hook
    if (mini_hook_install(ctors_addr, reinterpret_cast<void *>(proxy_call_constructors),
                          reinterpret_cast<void **>(&g_orig_call_constructors)) != 0) {
        DI_LOGE("hook: mini_hook_install(call_constructors) failed");
        return -1;
    }

    if (mini_hook_install(dtors_addr, reinterpret_cast<void *>(proxy_call_destructors),
                          reinterpret_cast<void **>(&g_orig_call_destructors)) != 0) {
        DI_LOGE("hook: mini_hook_install(call_destructors) failed");
        return -1;
    }

    DI_LOGI("hook: linker hooks installed successfully");
    return 0;
}

static int di_discover_offsets() {
    // Tell the proxy we're scanning (use our tid as the marker)
    g_scan_tid.store(gettid(), std::memory_order_release);

    // Load the dummy library — this triggers call_constructors, which runs our scan
    DI_LOGI("scan: loading dummy lib %s", DI_DUMMY_LIB_NAME);
    void *handle = dlopen(DI_DUMMY_LIB_NAME, RTLD_NOW);
    if (handle) dlclose(handle);

    // Done scanning
    g_scan_tid.store(0, std::memory_order_release);

    if (!handle) {
        DI_LOGE("scan: dlopen(%s) failed", DI_DUMMY_LIB_NAME);
        return -1;
    }
    if (!g_offsets_ready.load(std::memory_order_acquire)) {
        DI_LOGE("scan: offset discovery failed after dlopen");
        return -1;
    }

    return 0;
}

int dl_interceptor_init(void) {
    static pthread_mutex_t init_lock = PTHREAD_MUTEX_INITIALIZER;
    static int init_result = -1;
    static bool inited = false;

    if (inited) return init_result;

    pthread_mutex_lock(&init_lock);
    if (!inited) {
        inited = true;
        di_cb_list_init(&g_init_cbs);
        di_cb_list_init(&g_fini_cbs);

        DI_LOGI("init: starting (API level %d)", di_get_api_level());
        if (di_hook_linker() == 0 && di_discover_offsets() == 0) {
            init_result = 0;
            DI_LOGI("init: success");
        } else {
            DI_LOGE("init: failed");
        }
    }
    pthread_mutex_unlock(&init_lock);

    return init_result;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

int dl_interceptor_register_dl_init_callback(dl_interceptor_callback_t pre,
                                             dl_interceptor_callback_t post, void *data) {
    if (!pre && !post) return -1;
    return di_cb_list_add(&g_init_cbs, pre, post, data);
}

int dl_interceptor_unregister_dl_init_callback(dl_interceptor_callback_t pre,
                                               dl_interceptor_callback_t post, void *data) {
    return di_cb_list_remove(&g_init_cbs, pre, post, data);
}

int dl_interceptor_register_dl_fini_callback(dl_interceptor_callback_t pre,
                                             dl_interceptor_callback_t post, void *data) {
    if (!pre && !post) return -1;
    return di_cb_list_add(&g_fini_cbs, pre, post, data);
}

int dl_interceptor_unregister_dl_fini_callback(dl_interceptor_callback_t pre,
                                               dl_interceptor_callback_t post, void *data) {
    return di_cb_list_remove(&g_fini_cbs, pre, post, data);
}
