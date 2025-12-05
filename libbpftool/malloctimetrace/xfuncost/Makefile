BPF_CLANG ?= clang
BPF_CFLAGS ?= -g -O2 -target bpf -D__TARGET_ARCH_x86 -I./src

USER_CC ?= gcc
USER_CFLAGS ?= -g -O2 -Wall

SRC_DIR := src
BPF_OBJ := $(SRC_DIR)/xfuncost.bpf.o
USER_BIN :=  xfuncost
SKEL_HEADER := $(SRC_DIR)/xfuncost.skel.h
VMLINUX := $(SRC_DIR)/vmlinux.h

.PHONY: all clean

all: $(USER_BIN)

# Generate vmlinux.h from kernel BTF (CO-RE type info)
$(VMLINUX):
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

# Compile BPF program
$(BPF_OBJ): $(SRC_DIR)/xfuncost.bpf.c $(SRC_DIR)/common.h $(VMLINUX)
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@

# Generate libbpf skeleton header from BPF object
$(SKEL_HEADER): $(BPF_OBJ)
	bpftool gen skeleton $< > $@

# Compile user-space loader
$(USER_BIN): $(SRC_DIR)/xfuncost.c $(SRC_DIR)/common.h $(SKEL_HEADER)
	$(USER_CC) $(USER_CFLAGS) -I$(SRC_DIR) -o $@ $(SRC_DIR)/xfuncost.c -lbpf -lelf -lz

clean:
	rm -f $(BPF_OBJ) $(SKEL_HEADER) $(USER_BIN) $(VMLINUX)

