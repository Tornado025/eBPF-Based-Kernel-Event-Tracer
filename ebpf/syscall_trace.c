// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Syscall Trace - Trace system calls with process information
 * Equivalent C version of syscall_trace.bt
 * 
 * Compile: clang -O2 -target bpf -c syscall_trace.c -o syscall_trace.o
 * Load: bpftool prog load syscall_trace.o /sys/fs/bpf/syscall_trace
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/types.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} start_time_map SEC(".maps");

struct trace_event_raw_sys_enter {
    __u64 unused;
    long id;
    unsigned long args[6];
};

struct syscall_event {
    __u64 timestamp;
    __u32 pid;
    __u32 uid;
    char comm[16];
    long syscall_id;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

static __always_inline __u64 get_elapsed_ns(void) {
    __u32 key = 0;
    __u64 *start_ptr = bpf_map_lookup_elem(&start_time_map, &key);
    __u64 start = start_ptr ? *start_ptr : 0;
    return bpf_ktime_get_ns() - start;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int trace_syscall(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event event = {};
    
    event.timestamp = get_elapsed_ns();
    
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    event.pid = pid_tgid >> 32;
    
    __u64 uid_gid = bpf_get_current_uid_gid();
    event.uid = uid_gid & 0xFFFFFFFF;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.syscall_id = ctx->id;
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, 
                         &event, sizeof(event));
    return 0;
}
