#!/usr/bin/env python3

# Modular filtering, caching, and signal handling
# Multiple syscall coverage (open, write, close, rename, unlink, creat, mkdir)
# UID-to-username caching
# Interactive command mode with filtering
# In-memory buffer for post-filtering
# Ubuntu kernel version detection with resilient kprobe attachment
from bcc import BPF
import time
import pwd
import os
import datetime
import argparse
import signal
from collections import deque

# Parse command line arguments
parser = argparse.ArgumentParser(description='Monitor file modifications with filtering capabilities for Ubuntu Linux')
parser.add_argument('--live', action='store_true', help='Live monitoring mode (default)')
parser.add_argument('--filter', action='store_true', help='Filter events by username and time range')
parser.add_argument('--username', type=str, help='Filter events by this username')
parser.add_argument('--start-time', type=str, help='Start time for filtering (format: YYYY-MM-DD HH:MM)')
parser.add_argument('--end-time', type=str, help='End time for filtering (format: YYYY-MM-DD HH:MM)')
parser.add_argument('--buffer-size', type=int, default=10000, help='Number of events to keep in memory buffer (default: 10000)')
parser.add_argument('--command-interval', type=int, default=1, help='Polling interval for command mode checking (default: 1 second)')

args = parser.parse_args()

# Global flag to control mode switching
in_command_mode = False

# BPF program (unchanged)
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
        bpf_probe_read_str(&data.fname, sizeof(data.fname), (void *)filename);
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

// Track openat2 syscall (for newer Ubuntu kernels)
int trace_openat2(struct pt_regs *ctx, int dfd, const char __user *filename) {
    char op[] = "openat2";
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

# Detect Ubuntu kernel version
kernel_version = os.popen('uname -r').read().strip()
print(f"Detected kernel version: {kernel_version}")

# For Ubuntu-specific syscall naming
attach_kprobe_safe(b, "sys_open", "trace_open")
attach_kprobe_safe(b, "__x64_sys_open", "trace_open")
attach_kprobe_safe(b, "do_sys_open", "trace_open")  # Ubuntu specific

attach_kprobe_safe(b, "sys_openat", "trace_openat")
attach_kprobe_safe(b, "__x64_sys_openat", "trace_openat")
attach_kprobe_safe(b, "do_sys_openat", "trace_openat")  # Ubuntu specific

# For Ubuntu 20.04+ with 5.4+ kernel
attach_kprobe_safe(b, "sys_openat2", "trace_openat2")
attach_kprobe_safe(b, "__x64_sys_openat2", "trace_openat2")

attach_kprobe_safe(b, "sys_write", "trace_write")
attach_kprobe_safe(b, "__x64_sys_write", "trace_write")
attach_kprobe_safe(b, "ksys_write", "trace_write")  # Ubuntu specific

attach_kprobe_safe(b, "sys_close", "trace_close")
attach_kprobe_safe(b, "__x64_sys_close", "trace_close")
attach_kprobe_safe(b, "do_sys_close", "trace_close")  # Ubuntu specific

# Attach to rename syscalls
attach_kprobe_safe(b, "sys_rename", "trace_rename")
attach_kprobe_safe(b, "__x64_sys_rename", "trace_rename")
attach_kprobe_safe(b, "do_sys_rename", "trace_rename")  # Ubuntu specific

attach_kprobe_safe(b, "sys_renameat", "trace_renameat")
attach_kprobe_safe(b, "__x64_sys_renameat", "trace_renameat")

attach_kprobe_safe(b, "sys_renameat2", "trace_renameat2")
attach_kprobe_safe(b, "__x64_sys_renameat2", "trace_renameat2")

# Attach to unlink syscalls
attach_kprobe_safe(b, "sys_unlink", "trace_unlink")
attach_kprobe_safe(b, "__x64_sys_unlink", "trace_unlink")
attach_kprobe_safe(b, "do_unlinkat", "trace_unlink")  # Ubuntu specific

attach_kprobe_safe(b, "sys_unlinkat", "trace_unlinkat")
attach_kprobe_safe(b, "__x64_sys_unlinkat", "trace_unlinkat")

# Attach to create/mkdir syscalls
attach_kprobe_safe(b, "sys_creat", "trace_creat")
attach_kprobe_safe(b, "__x64_sys_creat", "trace_creat")

attach_kprobe_safe(b, "sys_mkdir", "trace_mkdir")
attach_kprobe_safe(b, "__x64_sys_mkdir", "trace_mkdir")
attach_kprobe_safe(b, "do_mkdirat", "trace_mkdir")  # Ubuntu specific

attach_kprobe_safe(b, "sys_mkdirat", "trace_mkdirat")
attach_kprobe_safe(b, "__x64_sys_mkdirat", "trace_mkdirat")

# User cache to avoid repeatedly looking up user names
user_cache = {}

# File descriptor cache to track open files by process
# Format: {pid: {fd: filename}}
fd_cache = {}

# In-memory buffer to store events for later filtering
event_buffer = deque(maxlen=args.buffer_size)

# Read /etc/passwd for all users
def load_user_map():
    for user in pwd.getpwall():
        user_cache[user.pw_uid] = user.pw_name
    return user_cache

# Cache username to UID mapping
def get_uid_by_username(username):
    for uid, name in user_cache.items():
        if name == username:
            return uid
    try:
        return pwd.getpwnam(username).pw_uid
    except KeyError:
        return None

# Format event information
def format_event_info(timestamp, username, uid, pid, comm, operation, filename):
    return f"[{timestamp}] User: {username} ({uid}), PID: {pid}, Comm: {comm}, Operation: {operation}, File: {filename}"

# Store events in memory buffer
def store_event(event_data):
    event_buffer.append(event_data)

# Filter events by username and time range
def filter_events(username=None, start_time=None, end_time=None):
    if username:
        target_uid = get_uid_by_username(username)
        if target_uid is None:
            print(f"Error: User '{username}' not found")
            return
    else:
        target_uid = None
    
    if start_time:
        try:
            start_dt = datetime.datetime.strptime(start_time, "%Y-%m-%d %H:%M")
        except ValueError:
            print("Error: Invalid start time format. Use YYYY-MM-DD HH:MM")
            return
    else:
        start_dt = None
    
    if end_time:
        try:
            end_dt = datetime.datetime.strptime(end_time, "%Y-%m-%d %H:%M")
        except ValueError:
            print("Error: Invalid end time format. Use YYYY-MM-DD HH:MM")
            return
    else:
        end_dt = None
    
    # Print header
    filter_conditions = []
    if username:
        filter_conditions.append(f"username='{username}'")
    if start_time:
        filter_conditions.append(f"start_time='{start_time}'")
    if end_time:
        filter_conditions.append(f"end_time='{end_time}'")
    
    print(f"\n=== Filtered events ({', '.join(filter_conditions)}) ===")
    
    # Count matches
    match_count = 0
    
    # Scan buffer for matching events
    for event_data in event_buffer:
        event_timestamp_str = event_data['timestamp']
        event_dt = datetime.datetime.strptime(event_timestamp_str, "%Y-%m-%d %H:%M:%S.%f")
        
        # Check time filter
        if start_dt and event_dt < start_dt:
            continue
        if end_dt and event_dt > end_dt:
            continue
        
        # Check username filter
        if target_uid is not None and event_data['uid'] != target_uid:
            continue
        
        # Print matching event
        print(format_event_info(
            event_data['timestamp'],
            event_data['username'],
            event_data['uid'],
            event_data['pid'],
            event_data['comm'],
            event_data['operation'],
            event_data['filename']
        ))
        match_count += 1
    
    print(f"\nFound {match_count} matching events.")

# Signal handler for Ctrl+C - switches to command mode
def signal_handler(signal, frame):
    global in_command_mode
    in_command_mode = True
    print("\nSwitching to command mode...")

# Register the signal handler
signal.signal(signal.SIGINT, signal_handler)

# Process events
def process_event(cpu, data, size):
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
    
    # Create event data for storage
    event_data = {
        'timestamp': timestamp,
        'username': username,
        'uid': event.uid,
        'pid': pid,
        'comm': comm,
        'operation': operation,
        'filename': filename
    }
    
    # Store in buffer for later filtering
    store_event(event_data)
    
    # Print in live mode
    if not args.filter:
        print(format_event_info(timestamp, username, event.uid, pid, comm, operation, filename))

    # Clean up fd_cache periodically (check if process still exists)
    if len(fd_cache) > 1000:  # Arbitrary limit to avoid memory issues
        for pid in list(fd_cache.keys()):
            if not os.path.exists(f"/proc/{pid}"):
                del fd_cache[pid]

# Interactive command mode
def command_mode():
    global in_command_mode
    
    help_text = """
Commands:
  filter <username> <start_time> <end_time>  - Filter events by username and time range
                                             - Example: filter manu_awasthi "2025-03-22 13:00" "2025-03-22 14:00"
                                             - Use "-" to skip a parameter: filter manu_awasthi - -
  getfileinfo <username> <start_time> <end_time> - Alias for filter command
  resume                                    - Resume monitoring mode
  exit                                      - Exit the program
  help                                      - Show this help
"""
    
    print(help_text)
    
    while True:
        try:
            cmd = input("\nEnter command (type 'help' for commands): ").strip()
            
            if cmd == "exit":
                print("Exiting...")
                return False  # Signal to exit the program
            elif cmd == "help":
                print(help_text)
            elif cmd == "resume":
                print("Resuming monitoring mode...")
                in_command_mode = False
                return True  # Signal to continue monitoring
            elif cmd.startswith("filter") or cmd.startswith("getfileinfo"):
                parts = cmd.split(maxsplit=3)
                if len(parts) < 2:
                    print("Error: Missing arguments. Use 'filter <username> [<start_time> <end_time>]'")
                else:
                    username = parts[1] if parts[1] != "-" else None
                    start_time = parts[2] if len(parts) > 2 and parts[2] != "-" else None
                    end_time = parts[3] if len(parts) > 3 and parts[3] != "-" else None
                    filter_events(username, start_time, end_time)
            else:
                print("Unknown command. Type 'help' for available commands.")
                
        except KeyboardInterrupt:
            print("\nUse 'exit' to quit or 'resume' to return to monitoring")

# Alternative command mode entry using keyboard input
def check_command_toggle():
    print("\nPress 'c' at any time to enter command mode.")
    print("Press Ctrl+C to exit the program.")
    
    import termios
    import tty
    import sys
    import select
    
    # Save terminal settings
    old_settings = termios.tcgetattr(sys.stdin)
    try:
        # Set terminal to raw mode
        tty.setraw(sys.stdin.fileno())
        
        # Check for keyboard input
        if select.select([sys.stdin], [], [], 0)[0]:
            key = sys.stdin.read(1)
            # If 'c' is pressed, enter command mode
            if key == 'c':
                return True
    finally:
        # Restore terminal settings
        termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)
    
    return False

# Load all users from /etc/passwd
load_user_map()

# Open event pipe
b["events"].open_perf_buffer(process_event)

if args.filter:
    # Filter mode - run for a specific time period and filter results
    print(f"Starting file modification monitoring in filter mode...")
    print(f"Collecting events to buffer (size: {args.buffer_size})...")
    print("Press Ctrl+C to switch to command mode or 'c' to directly enter command mode")
else:
    # Live mode
    print("Starting file modification monitoring in live mode...")
    print("Press Ctrl+C to switch to command mode or 'c' to directly enter command mode")

# Main event loop with command mode support
try:
    continue_running = True
    last_check_time = time.time()
    
    while continue_running:
        # Process BPF events with a timeout to allow interruption
        b.perf_buffer_poll(timeout=100)
        
        # Check if it's time to check for command mode toggle
        current_time = time.time()
        if current_time - last_check_time >= args.command_interval:
            last_check_time = current_time
            
            # Check if command mode is requested through signal handler
            if in_command_mode:
                # Enter command mode
                continue_running = command_mode()
            
            # Alternative: check for direct keyboard input
            try:
                if check_command_toggle():
                    in_command_mode = True
                    print("\nSwitching to command mode...")
                    continue_running = command_mode()
            except Exception as e:
                # If terminal input checking fails, fall back to signal-only
                pass
                
except KeyboardInterrupt:
    print("\nExiting program...")