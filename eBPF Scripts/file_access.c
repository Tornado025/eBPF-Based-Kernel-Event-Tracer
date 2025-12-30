// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * File Access Trace - Monitor file open/close operations
 * Equivalent C version of file_access.bt
 * 
 * Compile: clang -O2 -target bpf -c file_access.c -o file_access.o
 * Load: bpftool prog load file_access.o /sys/fs/bpf/file_access
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

struct open_event {
    __u64 timestamp;
    __u32 pid;
    char comm[16];
    char filename[256];
    __u8 event_type;  // 0=open, 1=openat
};

struct rw_event {
    __u64 timestamp;
    __u32 pid;
    char comm[16];
    __u32 fd;
    __u8 event_type;  // 2=read, 3=write, 4=close
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

SEC("tracepoint/syscalls/sys_enter_open")
int trace_open(struct trace_event_raw_sys_enter *ctx) {
    struct open_event event = {};
    
    event.timestamp = get_elapsed_ns();
    event.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user_str(&event.filename, sizeof(event.filename), 
                            (void *)ctx->args[0]);
    event.event_type = 0;
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, 
                         &event, sizeof(event));
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx) {
    struct open_event event = {};
    
    event.timestamp = get_elapsed_ns();
    event.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user_str(&event.filename, sizeof(event.filename), 
                            (void *)ctx->args[1]);
    event.event_type = 1;
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, 
                         &event, sizeof(event));
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_close")
int trace_close(struct trace_event_raw_sys_enter *ctx) {
    struct rw_event event = {};
    
    event.timestamp = get_elapsed_ns();
    event.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.fd = 0;
    event.event_type = 4;
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, 
                         &event, sizeof(event));
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_read")
int trace_read(struct trace_event_raw_sys_enter *ctx) {
    struct rw_event event = {};
    
    event.timestamp = get_elapsed_ns();
    event.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.fd = ctx->args[0];
    event.event_type = 2;
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, 
                         &event, sizeof(event));
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int trace_write(struct trace_event_raw_sys_enter *ctx) {
    struct rw_event event = {};
    
    event.timestamp = get_elapsed_ns();
    event.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.fd = ctx->args[0];
    event.event_type = 3;
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, 
                         &event, sizeof(event));
    return 0;
}
