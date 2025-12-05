// src/common.h
#ifndef __CONNECT_COMMON_H
#define __CONNECT_COMMON_H

// We want the same TASK_COMM_LEN on both BPF and user space side.
#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

// Common event structure sent via ring buffer.
// Both BPF program and user-space must see the exact same layout.
struct event_t {
    __u32 tgid;
    __u32 pid;
    size_t size;
    __u64 delta_ns;
    char comm[TASK_COMM_LEN];
};


/*
 * Runtime config shared between BPF program and user space.
 * 0 means "no filter".
 */
struct config {
    __u32 target_tgid;   // trace only this tgid, 0 = all
};


#endif /* __CONNECT_COMMON_H */
