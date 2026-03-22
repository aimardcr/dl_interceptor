LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := dl_interceptor_nothing
LOCAL_SRC_FILES := ../dl_interceptor_nothing.c
LOCAL_LDFLAGS := -Wl,--strip-all -Wl,--as-needed -Wl,--build-id=none -nostartfiles -nodefaultlibs
LOCAL_CFLAGS := -Oz -fno-ident -fno-unwind-tables -fno-asynchronous-unwind-tables
include $(BUILD_SHARED_LIBRARY)
