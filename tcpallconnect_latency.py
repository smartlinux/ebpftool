#!/usr/bin/env python3
# tcp_connect_rtt_all.py
#
# Measure TCP connect RTT (time from tcp_v4_connect() to TCP_ESTABLISHED)
# for both blocking and non-blocking connect(), using:
#   - kprobe: tcp_v4_connect      (start timestamp)
#   - tracepoint: sock:inet_sock_set_state (state -> TCP_ESTABLISHED)

from bcc import BPF
import socket
import struct

bpf_text = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <net/sock.h>

struct start_t {
    u64 ts;                 // timestamp at tcp_v4_connect()
    u32 tgid;               // process id (tgid)
    u32 pid;                // thread id (pid)
    char comm[TASK_COMM_LEN];  // process name at connect time
};

// One event per TCP connection that reaches TCP_ESTABLISHED
struct event_t {
    u32 tgid;
    u32 pid;
    u64 delta_ns;   // time from tcp_v4_connect() to TCP_ESTABLISHED

    u16 sport;      // source port (network byte order)
    u16 dport;      // dest port   (network byte order)
    u32 saddr;      // source IPv4 address (host byte order)
    u32 daddr;      // dest   IPv4 address (host byte order)

    char comm[TASK_COMM_LEN];  // process name from start_t
};

// Key: struct sock* (unique per TCP socket)
BPF_HASH(starts, struct sock *, struct start_t);

// Ring buffer for events
BPF_RINGBUF_OUTPUT(events, 1 << 12);

// kprobe on tcp_v4_connect: record start timestamp + process identity
int trace_tcp_v4_connect(struct pt_regs *ctx, struct sock *sk)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid  = (u32)pid_tgid;        // tid
    u32 tgid = pid_tgid >> 32;       // tgid

    struct start_t st = {};
    st.ts   = bpf_ktime_get_ns();
    st.tgid = tgid;
    st.pid  = pid;
    bpf_get_current_comm(&st.comm, sizeof(st.comm));

    starts.update(&sk, &st);
    return 0;
}

// tracepoint: sock:inet_sock_set_state
// fires on any TCP state change; we only care about:
//   - protocol == TCP
//   - family   == AF_INET
//   - newstate == TCP_ESTABLISHED
TRACEPOINT_PROBE(sock, inet_sock_set_state)
{
    // Only TCP
    if (args->protocol != IPPROTO_TCP)
        return 0;

    // Only IPv4
    if (args->family != AF_INET)
        return 0;

    // Only when the socket enters ESTABLISHED
    if (args->newstate != TCP_ESTABLISHED)
        return 0;

    struct sock *sk = (struct sock *)args->skaddr;

    struct start_t *stp = starts.lookup(&sk);
    if (!stp) {
        // We did not see tcp_v4_connect() for this socket
        // (could be passive accept or we attached too late)
        return 0;
    }

    u64 delta = bpf_ktime_get_ns() - stp->ts;

    struct event_t ev = {};
    ev.tgid     = stp->tgid;
    ev.pid      = stp->pid;
    ev.delta_ns = delta;

    // Copy comm from the time of tcp_v4_connect(), since this tracepoint
    // may run outside of the process context.
    __builtin_memcpy(&ev.comm, stp->comm, sizeof(ev.comm));

    // saddr/daddr are 4-byte arrays in network byte order in the tracepoint
    u32 saddr_net = 0;
    u32 daddr_net = 0;
    __builtin_memcpy(&saddr_net, args->saddr, sizeof(saddr_net));
    __builtin_memcpy(&daddr_net, args->daddr, sizeof(daddr_net));

    // Convert IPs to host byte order; keep ports in network byte order
    ev.saddr = bpf_ntohl(saddr_net);
    ev.daddr = bpf_ntohl(daddr_net);
    ev.sport = args->sport;
    ev.dport = args->dport;

    // We are done with this socket for connect RTT
    starts.delete(&sk);

    // Send event to user space via ring buffer
    events.ringbuf_output(&ev, sizeof(ev), 0);
    return 0;
}
"""

b = BPF(text=bpf_text)

# Attach kprobe and tracepoint
b.attach_kprobe(event="tcp_v4_connect", fn_name="trace_tcp_v4_connect")

# IMPORTANT: function name from TRACEPOINT_PROBE(sock, inet_sock_set_state)
# is "tracepoint__sock__inet_sock_set_state"
#b.attach_tracepoint(tp="sock:inet_sock_set_state",
#                    fn_name="tracepoint__sock__inet_sock_set_state")


def handle_event(ctx, data, size):
    event = b["events"].event(data)
    comm = event.comm.decode("utf-8", "replace").rstrip("\x00")

    # Convert IP/port for display
    src_ip = "-"
    dst_ip = "-"
    src_port = 0
    dst_port = 0

    if event.saddr != 0:
        src_ip = socket.inet_ntop(
            socket.AF_INET,
            struct.pack("!I", event.saddr)  # stored in host order, pack as network
        )
    if event.daddr != 0:
        dst_ip = socket.inet_ntop(
            socket.AF_INET,
            struct.pack("!I", event.daddr)
        )

    src_port = socket.ntohs(event.sport)
    dst_port = socket.ntohs(event.dport)

    ms = event.delta_ns / 1e6

    print(f"{comm:16s} tgid={event.tgid:6d} pid={event.pid:6d} "
          f"{src_ip}:{src_port:<5d} -> {dst_ip}:{dst_port:<5d} "
          f"connect_rtt={ms:7.3f} ms")


# Open ring buffer and poll
rb = b["events"]
rb.open_ring_buffer(handle_event)

print("Tracing TCP connect RTT via tcp_v4_connect + inet_sock_set_state ... Ctrl-C to quit")

while True:
    try:
        b.ring_buffer_poll()
    except KeyboardInterrupt:
        break
