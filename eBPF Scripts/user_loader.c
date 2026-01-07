// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * User-space loader for eBPF programs
 * Handles loading, attaching, and reading events from eBPF programs
 * 
 * Compile: gcc -o loader user_loader.c -lbpf -lelf -lz
 * Usage: ./loader <program.o>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/perf_event.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>

static volatile sig_atomic_t exiting = 0;

static void sig_handler(int sig) {
    exiting = 1;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    return vfprintf(stderr, format, args);
}

// Perf event setup
static int perf_event_open(struct perf_event_attr *attr, int pid, int cpu, int group_fd, unsigned long flags) {
    return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

// Handle perf event data
static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz) {
    // This is a generic handler - specific event structures would be defined
    // based on the eBPF program being loaded
    // printf("Event received: cpu=%d, size=%d\n", cpu, data_sz);
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt) {
    fprintf(stderr, "Lost %llu events on CPU %d\n", lost_cnt, cpu);
}

int main(int argc, char **argv) {
    struct bpf_object *obj = NULL;
    struct bpf_program *prog;
    struct bpf_map *map;
    struct perf_buffer *pb = NULL;
    int err = 0;
    int map_fd;
    __u32 key = 0;
    __u64 start_time;
    
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <bpf_object.o>\n", argv[0]);
        return 1;
    }
    
    // Set up libbpf errors and debug info callback
    libbpf_set_print(libbpf_print_fn);
    
    // Bump RLIMIT_MEMLOCK to allow BPF sub-system to do anything
    struct rlimit rlim_new = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };
    
    if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
        fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit: %s\n", strerror(errno));
        return 1;
    }
    
    // Load and verify BPF application
    obj = bpf_object__open_file(argv[1], NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open BPF object file: %s\n", argv[1]);
        return 1;
    }
    
    // Load BPF program
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Failed to load BPF object: %d\n", err);
        goto cleanup;
    }
    
    // Initialize start time in map
    map = bpf_object__find_map_by_name(obj, "start_time_map");
    if (map) {
        map_fd = bpf_map__fd(map);
        if (map_fd >= 0) {
            start_time = time(NULL) * 1000000000ULL;  // nanoseconds
            bpf_map_update_elem(map_fd, &key, &start_time, BPF_ANY);
            printf("{\"type\": \"trace_start\", \"timestamp\": %llu}\n", start_time);
        }
    }
    
    // Attach all programs
    bpf_object__for_each_program(prog, obj) {
        struct bpf_link *link = bpf_program__attach(prog);
        if (libbpf_get_error(link)) {
            fprintf(stderr, "Failed to attach BPF program '%s'\n",
                    bpf_program__name(prog));
            goto cleanup;
        }
        printf("Attached program: %s\n", bpf_program__name(prog));
    }
    
    // Set up perf buffer
    map = bpf_object__find_map_by_name(obj, "events");
    if (map) {
        struct perf_buffer_opts pb_opts = {};
        pb_opts.sz = sizeof(struct perf_buffer_opts);
        pb_opts.sample_cb = handle_event;
        pb_opts.lost_cb = handle_lost_events;

        pb = perf_buffer__new(bpf_map__fd(map), 8, &pb_opts);
        if (libbpf_get_error(pb)) {
            fprintf(stderr, "Failed to create perf buffer\n");
            err = -1;
            goto cleanup;
        }
    }
    
    // Set up signal handler
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    
    printf("Tracing... Press Ctrl+C to exit.\n");
    
    // Poll for events
    while (!exiting) {
        if (pb) {
            err = perf_buffer__poll(pb, 100);
            if (err < 0 && err != -EINTR) {
                fprintf(stderr, "Error polling perf buffer: %d\n", err);
                break;
            }
        } else {
            sleep(1);
        }
    }
    
    printf("\n{\"type\": \"trace_end\", \"timestamp\": %llu}\n", 
           time(NULL) * 1000000000ULL);

cleanup:
    perf_buffer__free(pb);
    bpf_object__close(obj);
    return err != 0;
}
