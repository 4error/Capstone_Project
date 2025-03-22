#!/usr/bin/env python3
from bcc import BPF
import time
import pwd
import os
import datetime

# Define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/fs.h>
#include <linux/sched.h>

// Data structure to pass event information to user space
struct data_t {
    u32 pid;
    u32 uid;
    u32 fd;
    u64 timestamp;
    char comm[TASK_COMM_LEN];
    char fname[256];
    char operation[16];
};

BPF_PERF_OUTPUT(events);

// Store string in char array
static inline void store_str(char *src, char *dst, size_t size) {
    #pragma unroll
    for (int i = 0; i < size && src[i]; i++) {
        dst[i] = src[i];
    }
}

// Common function to prepare and submit event data
static inline void submit_event(struct pt_regs *ctx, int fd, const char *filename, char *op) {
    struct data_t data = {};
    
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid();
    data.fd = fd;
    data.timestamp = bpf_ktime_get_ns();
    
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    
    if (filename) {
        bpf_probe_read_user_str(&data.fname, sizeof(data.fname), (void *)filename);
    }
    
    store_str(op, data.operation, sizeof(data.operation));
    
    events.perf_submit(ctx, &data, sizeof(data));
}

// Track open syscall (older version)
int trace_open(struct pt_regs *ctx, const char __user *filename, int flags) {
    // Only track if opening for writing
    if (!(flags & 0x1) && !(flags & 0x2)) 
        return 0;
        
    char op[] = "open";
    submit_event(ctx, 0, filename, op);
    return 0;
}

// Track openat syscall
int trace_openat(struct pt_regs *ctx, int dfd, const char __user *filename, int flags) {
    // Only track if opening for writing
    if (!(flags & 0x1) && !(flags & 0x2)) 
        return 0;
        
    char op[] = "openat";
    submit_event(ctx, 0, filename, op);
    return 0;
}

// Track write syscall
int trace_write(struct pt_regs *ctx, int fd, const void *buf, size_t count) {
    char op[] = "write";
    submit_event(ctx, fd, NULL, op);
    return 0;
}

// Track close syscall
int trace_close(struct pt_regs *ctx, unsigned int fd) {
    char op[] = "close";
    submit_event(ctx, fd, NULL, op);
    return 0;
}

// Track rename/renameat syscalls
int trace_rename(struct pt_regs *ctx, const char __user *oldname, const char __user *newname) {
    char op[] = "rename";
    submit_event(ctx, 0, newname, op);
    return 0;
}

int trace_renameat(struct pt_regs *ctx, int olddfd, const char __user *oldname, int newdfd, const char __user *newname) {
    char op[] = "renameat";
    submit_event(ctx, 0, newname, op);
    return 0;
}

int trace_renameat2(struct pt_regs *ctx, int olddfd, const char __user *oldname, int newdfd, const char __user *newname, unsigned int flags) {
    char op[] = "renameat2";
    submit_event(ctx, 0, newname, op);
    return 0;
}

// Track unlink/unlinkat syscalls
int trace_unlink(struct pt_regs *ctx, const char __user *pathname) {
    char op[] = "unlink";
    submit_event(ctx, 0, pathname, op);
    return 0;
}

int trace_unlinkat(struct pt_regs *ctx, int dfd, const char __user *pathname, int flag) {
    char op[] = "unlinkat";
    submit_event(ctx, 0, pathname, op);
    return 0;
}

// Track create/mkdir syscalls
int trace_creat(struct pt_regs *ctx, const char __user *pathname, mode_t mode) {
    char op[] = "creat";
    submit_event(ctx, 0, pathname, op);
    return 0;
}

int trace_mkdir(struct pt_regs *ctx, const char __user *pathname, mode_t mode) {
    char op[] = "mkdir";
    submit_event(ctx, 0, pathname, op);
    return 0;
}

int trace_mkdirat(struct pt_regs *ctx, int dfd, const char __user *pathname, mode_t mode) {
    char op[] = "mkdirat";
    submit_event(ctx, 0, pathname, op);
    return 0;
}
"""

# Load BPF program
b = BPF(text=bpf_text)

# Function to attempt attaching kprobes with error handling
def attach_kprobe_safe(bpf_obj, event, fn_name):
    try:
        bpf_obj.attach_kprobe(event=event, fn_name=fn_name)
        print(f"Successfully attached to {event}")
        return True
    except Exception as e:
        print(f"Warning: Failed to attach to {event}: {e}")
        return False

# Attach to core syscalls
attach_kprobe_safe(b, "sys_open", "trace_open")
attach_kprobe_safe(b, "__x64_sys_open", "trace_open")
attach_kprobe_safe(b, "sys_openat", "trace_openat")
attach_kprobe_safe(b, "__x64_sys_openat", "trace_openat")
attach_kprobe_safe(b, "sys_write", "trace_write")
attach_kprobe_safe(b, "__x64_sys_write", "trace_write")
attach_kprobe_safe(b, "sys_close", "trace_close")
attach_kprobe_safe(b, "__x64_sys_close", "trace_close")

# Attach to rename syscalls
attach_kprobe_safe(b, "sys_rename", "trace_rename")
attach_kprobe_safe(b, "__x64_sys_rename", "trace_rename")
attach_kprobe_safe(b, "sys_renameat", "trace_renameat")
attach_kprobe_safe(b, "__x64_sys_renameat", "trace_renameat")
attach_kprobe_safe(b, "sys_renameat2", "trace_renameat2")
attach_kprobe_safe(b, "__x64_sys_renameat2", "trace_renameat2")

# Attach to unlink syscalls
attach_kprobe_safe(b, "sys_unlink", "trace_unlink")
attach_kprobe_safe(b, "__x64_sys_unlink", "trace_unlink")
attach_kprobe_safe(b, "sys_unlinkat", "trace_unlinkat")
attach_kprobe_safe(b, "__x64_sys_unlinkat", "trace_unlinkat")

# Attach to create/mkdir syscalls
attach_kprobe_safe(b, "sys_creat", "trace_creat")
attach_kprobe_safe(b, "__x64_sys_creat", "trace_creat")
attach_kprobe_safe(b, "sys_mkdir", "trace_mkdir")
attach_kprobe_safe(b, "__x64_sys_mkdir", "trace_mkdir")
attach_kprobe_safe(b, "sys_mkdirat", "trace_mkdirat")
attach_kprobe_safe(b, "__x64_sys_mkdirat", "trace_mkdirat")

# User cache to avoid repeatedly looking up user names
user_cache = {}

# File descriptor cache to track open files by process
# Format: {pid: {fd: filename}}
fd_cache = {}

# Read /etc/passwd for all users
def load_user_map():
    for user in pwd.getpwall():
        user_cache[user.pw_uid] = user.pw_name
    return user_cache

# Process events
def print_event(cpu, data, size):
    event = b["events"].event(data)
    
    # Convert timestamp to human-readable format
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    
    # Get username from UID
    if event.uid in user_cache:
        username = user_cache[event.uid]
    else:
        try:
            username = pwd.getpwuid(event.uid).pw_name
            user_cache[event.uid] = username
        except:
            username = str(event.uid)
    
    pid = event.pid
    fd = event.fd
    operation = event.operation.decode('utf-8', 'replace').strip('\x00')
    comm = event.comm.decode('utf-8', 'replace').strip('\x00')
    filename = event.fname.decode('utf-8', 'replace').strip('\x00')
    
    # For write operations, try to resolve the file descriptor to a filename
    if operation == "write" and not filename:
        # Try to resolve using /proc
        proc_path = f"/proc/{pid}/fd/{fd}"
        try:
            if os.path.exists(proc_path):
                real_path = os.readlink(proc_path)
                filename = real_path
                
                # Update cache
                if pid not in fd_cache:
                    fd_cache[pid] = {}
                fd_cache[pid][fd] = filename
            else:
                filename = f"[fd {fd}]"
        except:
            filename = f"[fd {fd}]"
    
    # Print the event with timestamp
    print(f"[{timestamp}] User: {username} ({event.uid}), "
          f"PID: {pid}, Comm: {comm}, "
          f"Operation: {operation}, "
          f"File: {filename}")

    # Clean up fd_cache periodically (check if process still exists)
    if len(fd_cache) > 1000:  # Arbitrary limit to avoid memory issues
        for pid in list(fd_cache.keys()):
            if not os.path.exists(f"/proc/{pid}"):
                del fd_cache[pid]

# Load all users from /etc/passwd
load_user_map()

# Open event pipe
b["events"].open_perf_buffer(print_event)

print("Starting file modification monitoring... Press Ctrl+C to exit")

# Event loop
try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("Exiting...")