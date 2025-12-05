#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "common.h"

char LICENSE[] SEC("license") = "GPL";


struct start_t {
    __u64 ts;
    size_t size;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);          // tid
    __type(value, struct start_t);
} starts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

/* Global configuration (mapped to skeleton->rodata->cfg) */
const volatile struct config cfg = {};

SEC("uprobe//lib/x86_64-linux-gnu/libc.so.6:malloc")
int BPF_KPROBE(handle_malloc_enter, size_t size)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid  = pid_tgid;          // tid
    __u32 tgid = pid_tgid >> 32;    // tgid
    if (cfg.target_tgid && tgid != cfg.target_tgid)
        return 0;    
    struct start_t st = {};
    st.ts   = bpf_ktime_get_ns();
    st.size = size;
    bpf_map_update_elem(&starts, &pid, &st, BPF_ANY);
    return 0;
    
}

// uret, calculate time cost and send event to user space
SEC("uretprobe//lib/x86_64-linux-gnu/libc.so.6:malloc")
int BPF_KRETPROBE(handle_malloc_exit)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid  = pid_tgid;          // tid
    __u32 tgid = pid_tgid >> 32;    // tgid
    
    if (cfg.target_tgid && tgid != cfg.target_tgid)
        return 0;

    struct start_t *sp = bpf_map_lookup_elem(&starts, &pid);
    if (!sp)
        return 0;

    __u64 delta = bpf_ktime_get_ns() - sp->ts;
    size_t size = sp->size;
        
    bpf_map_delete_elem(&starts, &pid);
    
    /* Allocate event from ring buffer */
    struct event_t *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev)
        return 0;
        
    ev->tgid = tgid;
    ev->pid = pid;
    ev->size = size;
    ev->delta_ns = delta;    

    bpf_get_current_comm(&ev->comm, sizeof(ev->comm));

    bpf_ringbuf_submit(ev, 0);
    return 0;                
}
