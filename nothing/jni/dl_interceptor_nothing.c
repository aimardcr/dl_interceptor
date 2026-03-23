// Dummy shared library for dl_interceptor's soinfo memory scanning.
// This .so is dlopen'd at init time to trigger call_constructors(),
// allowing us to discover soinfo struct field offsets at runtime.
// It contains no useful code.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-variable"
static int dl_interceptor_nothing_unused = 0;
#pragma clang diagnostic pop
