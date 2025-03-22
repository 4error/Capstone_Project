from bcc import BPF
from datetime import datetime
import pwd

# eBPF C program
bpf_program = """
#include <linux/sched.h>
#include <uapi/linux/ptrace.h>

struct event_t {
    u32 pid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    u64 timestamp;
};

BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(sched, sched_process_exec) {
    struct event_t event = {};
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.timestamp = bpf_ktime_get_ns();

    events.perf_submit(args, &event, sizeof(event));
    return 0;
}
"""

# Load BPF program
b = BPF(text=bpf_program)

# Print header
print(f"{'TIME':<25} {'PID':<8} {'UID':<8} {'COMMAND':<20} {'USER':<15}")

# Function to resolve UID to username
def get_username(uid):
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return "UNKNOWN"

# Event callback
def print_event(cpu, data, size):
    event = b["events"].event(data)
    timestamp = datetime.fromtimestamp(event.timestamp / 1e9).strftime('%Y-%m-%d %H:%M:%S')

    # Convert byte strings to normal strings
    comm = event.comm.decode('utf-8', 'ignore')
    username = get_username(event.uid)

    print(f"{timestamp:<25} {event.pid:<8} {event.uid:<8} {comm:<20} {username:<15}")

# Open perf buffer
b["events"].open_perf_buffer(print_event)

# Poll for events
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        break
