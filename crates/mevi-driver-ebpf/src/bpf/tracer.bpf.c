// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __type(key, pid_t);
    __type(value, char);
    __uint(max_entries, 1024);
} tracees SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    // TODO: Benchmark to figure out optimal size, or allow configuration at
    // runtime using an environment variable.
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

__always_inline static pid_t getpid(void)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    return pid_tgid & __UINT32_MAX__;
}

#define ON_EXIT(_Name)                          \
    SEC("tracepoint/syscalls/sys_exit_" #_Name) \
    int on_exit_##_Name(struct trace_event_raw_sys_exit* ctx)

#define ON_ENTER(_Name)                          \
    SEC("tracepoint/syscalls/sys_enter_" #_Name) \
    int on_enter_##_Name(struct trace_event_raw_sys_enter* ctx)

ON_EXIT(clone)
{
    return 0;
}

ON_EXIT(fork)
{
    return 0;
}

ON_EXIT(vfork)
{
    return 0;
}

ON_EXIT(exec)
{
    return 0;
}

ON_ENTER(exit)
{
    return 0;
}

ON_EXIT(mmap)
{
    return 0;
}

ON_EXIT(mremap)
{
    return 0;
}

ON_EXIT(munmap)
{
    return 0;
}

ON_EXIT(madvise)
{
    return 0;
}

ON_EXIT(brk)
{
    return 0;
}
