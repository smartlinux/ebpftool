#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "common.h"

#include "xfuncost.skel.h"

static volatile sig_atomic_t exiting = 0;
static int target_pid  = 0;
static void handle_sigint(int sig) { exiting = 1; }
static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [OPTIONS]\n"
        "  -p <pid>    filter by tgid\n",
        prog);
}

// Optional: libbpf logging callback
static int libbpf_print_fn(enum libbpf_print_level level,
                           const char *format, va_list args)
{
    if (level == LIBBPF_DEBUG)
        return 0; // skip debug logs

    return vfprintf(stderr, format, args);
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct event_t *ev = data;

    double delta = ev->delta_ns / 1e6;


    printf("%-16s tgid=%-6u pid=%-6u "
       "size=%8zu cost=%7.3f ms\n",
       ev->comm,
       ev->tgid,
       ev->pid,
       ev->size,
       delta);

    return 0;
}

int main(int argc, char **argv)
{
    struct ring_buffer *rb = NULL;
    struct xfuncost_bpf *skel = NULL;
    int err;
    int opt;

    /* Attach uprobes to libc connect */
    const char *libc_path = "/lib/x86_64-linux-gnu/libc.so.6";
    // Parse command-line options
    while ((opt = getopt(argc, argv, "hp:")) != -1) {
        switch (opt) {
        case 'p':
            target_pid = atoi(optarg);
            if (target_pid <= 0) {
                fprintf(stderr, "Invalid PID (tgid): %d\n", target_pid);
                return 1;
            }
            break;
        case 'h':
        default:
            usage(argv[0]);
            return 1;
        }
    }

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(libbpf_print_fn);

    signal(SIGINT, handle_sigint);
    signal(SIGTERM, handle_sigint);

    skel = xfuncost_bpf__open();
    if (!skel) { fprintf(stderr, "Open ebpf prog failed\n"); }

    skel->rodata->cfg.target_tgid  = target_pid;
    
    err = xfuncost_bpf__load(skel);
    if (err)  { fprintf(stderr, "Load ebpf prog failed\n"); }
  
 
    // Attach kprobes
    err = xfuncost_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF programs: %d\n", err);
        goto cleanup;
    }

    // Set up ring buffer to receive events
    rb = ring_buffer__new(bpf_map__fd(skel->maps.events),
                          handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        err = 1;
        goto cleanup;
    }

    printf("Tracing function in %s ... Ctrl-C to exit\n", libc_path);


    while (!exiting) {
        err = ring_buffer__poll(rb, 100 /* timeout ms */);
        if (err == -EINTR) {
            // Interrupted by signal
            break;
        } else if (err < 0) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
        // err == 0: timeout, simply continue
    }

cleanup:

    ring_buffer__free(rb);
    xfuncost_bpf__destroy(skel);
    return err != 0;

}
