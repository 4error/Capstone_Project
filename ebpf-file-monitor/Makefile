# Makefile (Final Version with Automatic vmlinux.h Generation)

# Dirs
APP_DIR := .
OUT_DIR := .
BPF_DIR := $(APP_DIR)
VMLINUX_H := $(OUT_DIR)/vmlinux.h
BPF_OBJ := $(OUT_DIR)/monitor.bpf.o
BPF_SKEL := $(OUT_DIR)/monitor.skel.h
APP_BIN := $(OUT_DIR)/monitor

# Compiler and flags
CC = gcc
CLANG = clang
CFLAGS = -g -Wall
LIB_FLAGS = -lelf -lbpf

# Dynamically determine architecture for correct paths and flags
ARCH := $(shell uname -m)
ifeq ($(ARCH),aarch64)
    TARGET_ARCH_FLAG := -D__TARGET_ARCH_arm64
else
    TARGET_ARCH_FLAG := -D__TARGET_ARCH_x86
endif
ARCH_INCLUDE_PATH := -I/usr/include/$(ARCH)-linux-gnu

all: $(APP_BIN)

# Rule to automatically generate vmlinux.h if it's missing
# NOTE: This requires 'make' to be run with sudo
$(VMLINUX_H):
	@echo "  GEN-CORE  $(VMLINUX_H)"
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX_H)

# Rule for building the BPF object file. It now depends on vmlinux.h!
$(BPF_OBJ): $(BPF_DIR)/monitor.bpf.c $(APP_DIR)/common.h $(VMLINUX_H)
	@echo "  CLANG-BPF $(BPF_OBJ)"
	$(CLANG) -g -O2 -target bpf $(TARGET_ARCH_FLAG) \
		$(ARCH_INCLUDE_PATH) \
		-c $(BPF_DIR)/monitor.bpf.c -o $(BPF_OBJ)

# Rule for generating the BPF skeleton header
$(BPF_SKEL): $(BPF_OBJ)
	@echo "  GEN-SKEL  $(BPF_SKEL)"
	bpftool gen skeleton $(BPF_OBJ) > $(BPF_SKEL)

# Rule for building the userspace application
$(APP_BIN): $(APP_DIR)/monitor.c $(BPF_SKEL)
	@echo "  CC        $(APP_BIN)"
	$(CC) $(CFLAGS) $(APP_DIR)/monitor.c -o $(APP_BIN) $(LIB_FLAGS)

clean:
	rm -f $(BPF_OBJ) $(BPF_SKEL) $(APP_BIN) $(VMLINUX_H) *.o

.PHONY: all clean