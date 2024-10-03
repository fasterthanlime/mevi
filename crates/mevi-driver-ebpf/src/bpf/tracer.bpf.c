// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
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

enum tracee_kind {
    TRACEE_KIND_MEVI = 0,
    TRACEE_KIND_PROC = 1,
};

enum memory_state {
    MEMORY_STATE_RESIDENT = 1,
    MEMORY_STATE_NOT_RESIDENT = 2,
    MEMORY_STATE_UNTRACKED = 3,
};

struct memory_range {
    __u64 start;
    __u64 end;
};

enum memory_change_kind {
    MEMORY_CHANGE_KIND_MAP = 1,
    MEMORY_CHANGE_KIND_REMAP = 2,
    MEMORY_CHANGE_KIND_UNMAP = 3,
    MEMORY_CHANGE_KIND_PAGE_OUT = 4,
};

struct memory_change {
    enum memory_change_kind kind;
    union {
        struct {
            struct memory_range range;
            enum memory_state state;
        } map;
        struct {
            struct memory_range old_range;
            struct memory_range new_range;
        } remap;
        struct {
            struct memory_range range;
        } unmap;
        struct {
            struct memory_range range;
        } page_out;
    };
};

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
