#!/usr/bin/python3
from bcc import BPF
from datetime import datetime
import argparse
import ctypes as ct
import pwd
import os
import signal
import sys
import time

# Parse command-line arguments
parser = argparse.ArgumentParser(description='Track user logins using eBPF')
parser.add_argument('--output', '-o', default='console',
                   help='Output format: console, csv, or json')
parser.add_argument('--file', '-f', default='logins.log',
                   help='File to save output to (if using csv/json output)')
args = parser.parse_args()

# Define eBPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct login_event_t {
    u64 timestamp;
    u32 uid;
    u32 pid;
    u32 ppid;
    char comm[TASK_COMM_LEN];
    char username[32];
    u8 success;
};

BPF_PERF_OUTPUT(events);
BPF_HASH(auth_cache, u32, struct login_event_t);

static u32 get_parent_pid(struct task_struct *task) {
    struct task_struct *parent;
    u32 ppid = 0;
    
    bpf_probe_read(&parent, sizeof(parent), &task->real_parent);
    if (parent) {
        ppid = parent->tgid;
    }
    
    return ppid;
}

static inline void prepare_login_event(struct login_event_t *event, struct pt_regs *ctx) {
    event->timestamp = bpf_ktime_get_ns();
    event->success = 0;
    
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    event->pid = pid;
    
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    event->ppid = get_parent_pid(task);
    
    event->username[0] = '\\0';
}

// PAM authentication
int trace_pam_auth(struct pt_regs *ctx, const char *user) {
    struct login_event_t event = {};
    prepare_login_event(&event, ctx);
    
    if (user) {
        bpf_probe_read_str(event.username, sizeof(event.username), (void *)user);
    }
    
    u32 pid = event.pid;
    auth_cache.update(&pid, &event);
    return 0;
}

// PAM success
int trace_pam_success(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct login_event_t *cached = auth_cache.lookup(&pid);
    
    if (cached) {
        struct login_event_t event = *cached;
        event.success = 1;
        event.timestamp = bpf_ktime_get_ns();
        events.perf_submit(ctx, &event, sizeof(event));
        auth_cache.delete(&pid);
    }
    
    return 0;
}

// SSH login
int trace_sshd_login(struct pt_regs *ctx, char *user) {
    struct login_event_t event = {};
    prepare_login_event(&event, ctx);
    
    if (user) {
        bpf_probe_read_str(event.username, sizeof(event.username), (void *)user);
    }
    
    event.success = 1;
    
    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

// sudo execution
int trace_sudo_exec(struct pt_regs *ctx) {
    struct login_event_t event = {};
    prepare_login_event(&event, ctx);
    
    if (event.comm[0] == 's' && event.comm[1] == 'u' && event.comm[2] == 'd' && event.comm[3] == 'o') {
        events.perf_submit(ctx, &event, sizeof(event));
    }
    
    return 0;
}

// su switch
int trace_su_switch(struct pt_regs *ctx) {
    struct login_event_t event = {};
    prepare_login_event(&event, ctx);
    
    if (event.comm[0] == 's' && event.comm[1] == 'u' && event.comm[2] == '\\0') {
        events.perf_submit(ctx, &event, sizeof(event));
    }
    
    return 0;
}
"""

# Define output file if needed
output_file = None
if args.output != 'console':
    output_file = open(args.file, 'w')
    if args.output == 'csv':
        output_file.write("timestamp,uid,username,pid,ppid,process,success\n")

# Load BPF
b = BPF(text=bpf_text)

# Attach probes
b.attach_uprobe(name="/lib/x86_64-linux-gnu/libpam.so.0.85.1", addr=0x9de0, fn_name="trace_pam_auth")

b.attach_uretprobe(name="/lib/x86_64-linux-gnu/libpam.so.0.85.1", sym="pam_authenticate", fn_name="trace_pam_success")

b.attach_uprobe(name="/usr/sbin/sshd", sym="do_authentication", fn_name="trace_sshd_login")

b.attach_kprobe(event="do_execve", fn_name="trace_sudo_exec")
b.attach_kprobe(event="do_execve", fn_name="trace_su_switch")

# Define structure for handling events
class LoginEvent(ct.Structure):
    _fields_ = [
        ("timestamp", ct.c_ulonglong),
        ("uid", ct.c_uint),
        ("pid", ct.c_uint),
        ("ppid", ct.c_uint),
        ("comm", ct.c_char * 16),
        ("username", ct.c_char * 32),
        ("success", ct.c_ubyte),
    ]

# Get username from UID
def get_username_from_uid(uid):
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return f"uid:{uid}"

# Handle exit
def signal_handler(sig, frame):
    if output_file:
        output_file.close()
    print("\nExiting...")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

# Print header
if args.output == 'console':
    print("%-19s %-12s %-16s %-5s %-20s %s" % 
          ("TIME", "USERNAME", "EVENT", "PID", "PROCESS", "STATUS"))

# Process events
def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(LoginEvent)).contents
    time_str = datetime.fromtimestamp(event.timestamp / 1e9).strftime("%Y-%m-%d %H:%M:%S")
    username = event.username.decode('utf-8', 'replace') or get_username_from_uid(event.uid)
    process = event.comm.decode('utf-8', 'replace')
    status = "SUCCESS" if event.success else "ATTEMPT"

    if args.output == 'console':
        print("%-19s %-12s %-16s %-5d %-20s %s" % 
              (time_str, username, "LOGIN", event.pid, process, status))
    elif args.output == 'csv':
        output_file.write(f"{event.timestamp},{event.uid},{username},{event.pid},"
                          f"{event.ppid},{process},{status}\n")
        output_file.flush()
    elif args.output == 'json':
        import json
        json_entry = {"timestamp": event.timestamp, "datetime": time_str,
                      "uid": event.uid, "username": username, "pid": event.pid,
                      "ppid": event.ppid, "process": process, "success": bool(event.success)}
        output_file.write(json.dumps(json_entry) + "\n")
        output_file.flush()

# Poll for events
b["events"].open_perf_buffer(print_event)
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        if output_file:
            output_file.close()
        break
