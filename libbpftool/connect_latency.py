#!/usr/bin/env python3
from bcc import BPF
import socket
import struct

bpf_text = r"""
#include <uapi/linux/ptrace.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/sched.h>

struct event_t {
    u32 tgid;
    u32 pid;
    u64 delta_ns;   // Duration of the connect phase
    int ret;
    int fd;
    u16 family;
    u16 dport;
    u32 daddr;      // IPv4, network order or host order, depending on convention
    char comm[TASK_COMM_LEN];
};

struct conn_t {
    u64 ts;
    int fd;
    u16 family;
    u16 dport;
    u32 daddr;
};

struct key_t {
    u32 pid;   // tid

};

BPF_HASH(start, struct key_t, struct conn_t, 10240);

BPF_PERF_OUTPUT(events);

// sys_enter_connect: Record start timestamp + destination address
TRACEPOINT_PROBE(syscalls, sys_enter_connect)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = (u32)pid_tgid;


    struct key_t k = {};
    k.pid = pid;


    struct conn_t c = {};
    c.ts = bpf_ktime_get_ns();
    c.fd = args->fd;

    const struct sockaddr *usaddr =
        (const struct sockaddr *)args->uservaddr;

    if (usaddr) {
        u16 family = 0;
        bpf_probe_read_user(&family, sizeof(family),
                            &usaddr->sa_family);
        c.family = family;

        if (family == AF_INET) {
            struct sockaddr_in sa4 = {};
            bpf_probe_read_user(&sa4, sizeof(sa4), usaddr);
            // Consistent with your previous style: use bpf_ntohl here
            c.daddr = bpf_ntohl(sa4.sin_addr.s_addr);
            c.dport = sa4.sin_port;
        }
    }

    start.update(&k, &c);
    return 0;
}

// sys_exit_connect: Calculate duration, only report successful blocking connects + IPv4
TRACEPOINT_PROBE(syscalls, sys_exit_connect)
{

    // Only keep successful connections (blocking connect usually returns 0)
    if (args->ret != 0)
        return 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = (u32)pid_tgid;

    struct key_t k = {};
    k.pid = pid;


    struct conn_t *cp = start.lookup(&k);
    if (!cp) {
        return 0;
    }

    // Only keep IPv4
    if (cp->family != AF_INET)
        return 0;

    u64 delta = bpf_ktime_get_ns() - cp->ts;

    struct event_t ev = {};
    ev.pid = pid;
    ev.tgid = pid_tgid >> 32;
    ev.delta_ns = delta;
    ev.ret = args->ret;
    ev.fd = cp->fd;
    ev.family = cp->family;
    ev.dport = cp->dport;
    ev.daddr = cp->daddr;
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));

    start.delete(&k);




    events.perf_submit(args, &ev, sizeof(ev));
    return 0;
}
"""
def main():
    b = BPF(text=bpf_text)
    
    def print_event(cpu, data, size):
        event = b["events"].event(data)
        comm = event.comm.decode("utf-8", "replace").rstrip("\x00")
    
        # Optional: Filter for curl only for easier debugging
        # if comm != "curl":
        #     return
    
        ip = "-"
        port = 0
        if event.family == socket.AF_INET and event.daddr != 0:  # AF_INET
            # Note: We used bpf_ntohl in BPF,
            # so use "!I" (network byte order) to pack in Python:
            ip = socket.inet_ntop(
                socket.AF_INET,
                struct.pack("!I", event.daddr)
            )
            port = socket.ntohs(event.dport)
    
        ms = event.delta_ns / 1e6
    
        print(f"{comm:16s} pid={event.pid:6d} tgid={event.tgid:6d} "
              f"fd={event.fd:3d} {ip}:{port:<5d} "
              f"ret={event.ret:4d} rtt={ms:7.3f} ms")
    
    b["events"].open_perf_buffer(print_event)
    
    print("Tracing blocking IPv4 connect RTT via sys_enter/exit_connect ... Ctrl-C to quit")
    
    while True:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            break
        
        
if __name__ == "__main__":
    main()