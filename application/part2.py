from bcc import BPF

bpf_program = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

BPF_PERF_OUTPUT(events);

struct data_t {
    u32 pid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    char filename[NAME_MAX];
};

static int get_filename(struct pt_regs *ctx, struct data_t *data, struct dentry *dentry) {
    if (!dentry)
        return 0;
    bpf_probe_read_kernel(&data->filename, sizeof(data->filename), dentry->d_name.name);
    return 1;
}

int trace_open(struct pt_regs *ctx, struct file *file) {
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    
    if (get_filename(ctx, &data, file->f_path.dentry)) {
        events.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int trace_write(struct pt_regs *ctx, struct file *file) {
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    
    if (get_filename(ctx, &data, file->f_path.dentry)) {
        events.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int trace_rename(struct pt_regs *ctx, struct dentry *old_dentry, struct dentry *new_dentry) {
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    
    if (get_filename(ctx, &data, old_dentry)) {
        events.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}
"""

b = BPF(text=bpf_program)
b.attach_kprobe(event="vfs_open", fn_name="trace_open")
b.attach_kprobe(event="vfs_write", fn_name="trace_write")
b.attach_kprobe(event="vfs_rename", fn_name="trace_rename")

def print_event(cpu, data, size):
    event = b['events'].event(data)
    print(f"PID {event.pid} ({event.comm}) modified {event.filename}")

b['events'].open_perf_buffer(print_event)

print("Tracing file modifications... Press Ctrl+C to exit.")
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()

