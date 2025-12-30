# Makefile for eBPF programs
# Compiles both BPF kernel programs and user-space loaders

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

# Compile BPF programs
%.o: %.c
	$(CLANG) $(BPF_CFLAGS) $(INCLUDES) -c $< -o $@
	@echo "Compiled BPF program: $@"

# Compile user-space loader
user_loader: user_loader.c
	$(CC) -o $@ $< -lbpf -lelf -lz
	@echo "Compiled user-space loader: $@"


clean:
	rm -f $(BPF_PROGS) $(LOADERS)
	@echo "Cleaned build artifacts"

# Individual targets
file_access.o: file_access.c
memory_trace.o: memory_trace.c
syscall_trace.o: syscall_trace.c

# Help target
help:
	@echo "eBPF Build System"
	@echo "================="
	@echo "Targets:"
	@echo "  all          - Build all BPF programs and loaders (default)"
	@echo "  clean        - Remove all build artifacts"
	@echo "  help         - Show this help message"
	@echo ""
	@echo "Usage Examples:"
	@echo "  make                    # Build everything"
	@echo "  make file_access.o      # Build specific BPF program"
	@echo "  make clean              # Clean build artifacts"
	@echo ""
	@echo "Loading Programs:"
	@echo "  sudo ./user_loader syscall_trace.o"

	@echo "  ./user_loader file_access.o"
	@echo "  sudo bpftool prog load file_access.o /sys/fs/bpf/file_access"
