// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Memory Trace - Monitor memory allocation and deallocation
 * Equivalent C version of memory_trace.bt
 * 
 * Compile: clang -O2 -target bpf -c memory_trace.c -o memory_trace.o
 * Load: bpftool prog load memory_trace.o /sys/fs/bpf/memory_trace
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

struct mmap_event {
    __u64 timestamp;
    __u32 pid;
    char comm[16];
    __u64 length;
    __u32 flags;
    __u8 event_type;  // 0=mmap, 1=munmap
};

struct mem_event {
    __u64 timestamp;
    __u32 pid;
    char comm[16];
    __u32 behavior;
    __u8 event_type;  // 2=brk, 3=madvise
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

SEC("tracepoint/syscalls/sys_enter_mmap")
int trace_mmap(struct trace_event_raw_sys_enter *ctx) {
    struct mmap_event event = {};
    
    event.timestamp = get_elapsed_ns();
    event.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.length = ctx->args[1];
    event.flags = ctx->args[3];
    event.event_type = 0;
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, 
                         &event, sizeof(event));
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_munmap")
int trace_munmap(struct trace_event_raw_sys_enter *ctx) {
    struct mmap_event event = {};
    
    event.timestamp = get_elapsed_ns();
    event.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.length = ctx->args[1];
    event.flags = 0;
    event.event_type = 1;
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, 
                         &event, sizeof(event));
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_brk")
int trace_brk(struct trace_event_raw_sys_enter *ctx) {
    struct mem_event event = {};
    
    event.timestamp = get_elapsed_ns();
    event.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.behavior = 0;
    event.event_type = 2;
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, 
                         &event, sizeof(event));
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_madvise")
int trace_madvise(struct trace_event_raw_sys_enter *ctx) {
    struct mem_event event = {};
    
    event.timestamp = get_elapsed_ns();
    event.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.behavior = ctx->args[2];
    event.event_type = 3;
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, 
                         &event, sizeof(event));
    return 0;
}
