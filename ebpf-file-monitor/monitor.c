// monitor.c

#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include "common.h"
#include "monitor.skel.h"
#include <cerrno>

static volatile bool exiting = false;

static void sig_handler(int sig) {
    exiting = true;
}

const char *op_to_str(enum fs_op_type op) {
    switch(op) {
        case FS_OP_CLOSE: return "CLOSE_WRITE";
        case FS_OP_SYNC: return "SYNC";
        case FS_OP_WRITEV: return "WRITEV";
        case FS_OP_SPLICE: return "SPLICE";
        case FS_OP_TRUNCATE: return "TRUNCATE";
        case FS_OP_RENAME: return "RENAME";
        default: return "UNKNOWN";
    }
}

int handle_event(void *ctx, void *data, size_t data_sz) {
    const struct event *e = data;
    printf("%-16s %-7d %-7d %-12s %-12llu ",
           e->comm, e->pid, e->ppid, op_to_str(e->op), e->mnt_ns_id);

    if (e->op == FS_OP_RENAME) {
        printf("'%s' -> '%s'\n", e->old_path, e->path);
    } else {
        printf("'%s'\n", e->path);
    }
    
    return 0;
}

int main(int argc, char **argv) {
    struct ring_buffer *rb = NULL;
    struct monitor_bpf *skel;
    int err;

    skel = monitor_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }
    
    err = monitor_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    err = monitor_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }
    
    printf("Successfully started! Please wait for events...\n");
    printf("%-16s %-7s %-7s %-12s %-12s %s\n",
           "COMM", "PID", "PPID", "OPERATION", "MNT_NS", "PATH");

    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    while (!exiting) {
        err = ring_buffer__poll(rb, 100 /* timeout, ms */);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            printf("Error polling ring buffer: %d\n", err);
            break;
        }
    }

cleanup:
    ring_buffer__free(rb);
    monitor_bpf__destroy(skel);
    return -err;
}