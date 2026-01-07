CLANG ?= clang
LLC ?= llc
CC ?= gcc
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

BPF_CFLAGS := -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -g
INCLUDES := -I/usr/include -I/usr/include/$(shell uname -m)-linux-gnu

BPF_PROGS := file_access.o memory_trace.o syscall_trace.o
LOADERS := user_loader

.PHONY: all clean

all: $(BPF_PROGS) $(LOADERS)

%.o: %.c
	$(CLANG) $(BPF_CFLAGS) $(INCLUDES) -c $< -o $@
	@echo "Compiled BPF program: $@"

user_loader: user_loader.c
	$(CC) -o $@ $< -lbpf -lelf -lz
	@echo "Compiled user-space loader: $@"


clean:
	rm -f $(BPF_PROGS) $(LOADERS)
	@echo "Cleaned build artifacts"

file_access.o: file_access.c
memory_trace.o: memory_trace.c
syscall_trace.o: syscall_trace.c
