#!/usr/bin/env python3

# resolving conflicts, not the main file
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

# BPF program (optimized to avoid stack limit issues)
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

// Structure for open event tracking
struct opendata_t {
    char fname[256];
};

BPF_PERF_OUTPUT(events);

// Map to track opened files: pid+fd -> filename
BPF_HASH(openfiles, u64, struct opendata_t);

// Per-CPU array to store temporary large data
BPF_PERCPU_ARRAY(tmp_data, struct data_t, 1);

// Store string in char array with bounds checking
static inline void store_str(char *src, char *dst, size_t size) {
    if (!src || !dst)
        return;
        
    #pragma unroll
    for (int i = 0; i < size && src[i]; i++) {
        dst[i] = src[i];
    }
}

// Common function to prepare and submit event data
static inline void submit_event(struct pt_regs *ctx, int fd, const char *filename, char *op) {
    int zero = 0;
    struct data_t *data = tmp_data.lookup(&zero);
    if (!data)
        return;
    
    __builtin_memset(data, 0, sizeof(*data));
    
    data->pid = bpf_get_current_pid_tgid() >> 32;
    data->uid = bpf_get_current_uid_gid();
    data->fd = fd;
    data->timestamp = bpf_ktime_get_ns();
    
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    
    if (filename) {
        bpf_probe_read_str(data->fname, sizeof(data->fname), (void *)filename);
    } else if (fd > 0) {
        // For operations like write/close, try to fetch filename from our map
        u64 pid_fd = ((u64)data->pid << 32) | fd;
        struct opendata_t *filedata = openfiles.lookup(&pid_fd);
        if (filedata) {
            __builtin_memcpy(&data->fname, &filedata->fname, sizeof(data->fname));
        }
    }
    
    if (op) {
        store_str(op, data->operation, sizeof(data->operation));
    }
    
    events.perf_submit(ctx, data, sizeof(*data));
}

// Track open syscall
int trace_open_enter(struct pt_regs *ctx, const char __user *filename, int flags) {
    // Only track if opening for writing
    if (!(flags & 0x1) && !(flags & 0x2)) 
        return 0;
        
    char op[] = "open";
    submit_event(ctx, 0, filename, op);
    return 0;
}

int trace_open_return(struct pt_regs *ctx) {
    int fd = PT_REGS_RC(ctx);  // Get return value (file descriptor)
    if (fd < 0) return 0;      // Failed open
    
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 pid_fd = ((u64)pid << 32) | fd;
    
    // We can't directly access the filename here as it was in the entry function
    // We'll rely on /proc filesystem in userspace for this
    struct opendata_t filedata = {};
    openfiles.update(&pid_fd, &filedata);
    
    return 0;
}

// Track openat syscall
int trace_openat_enter(struct pt_regs *ctx, int dfd, const char __user *filename, int flags) {
    // Only track if opening for writing
    if (!(flags & 0x1) && !(flags & 0x2)) 
        return 0;
        
    char op[] = "openat";
    submit_event(ctx, 0, filename, op);
    return 0;
}

int trace_openat_return(struct pt_regs *ctx) {
    int fd = PT_REGS_RC(ctx);  // Get return value (file descriptor)
    if (fd < 0) return 0;      // Failed open
    
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 pid_fd = ((u64)pid << 32) | fd;
    
    struct opendata_t filedata = {};
    openfiles.update(&pid_fd, &filedata);
    
    return 0;
}

// Track openat2 syscall
int trace_openat2_enter(struct pt_regs *ctx, int dfd, const char __user *filename) {
    char op[] = "openat2";
    submit_event(ctx, 0, filename, op);
    return 0;
}

int trace_openat2_return(struct pt_regs *ctx) {
    int fd = PT_REGS_RC(ctx);  // Get return value (file descriptor)
    if (fd < 0) return 0;      // Failed open
    
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 pid_fd = ((u64)pid << 32) | fd;
    
    struct opendata_t filedata = {};
    openfiles.update(&pid_fd, &filedata);
    
    return 0;
}

// Track write syscall
int trace_write(struct pt_regs *ctx, int fd, const void *buf, size_t count) {
    if (fd <= 0) return 0;
    
    char op[] = "write";
    submit_event(ctx, fd, NULL, op);
    return 0;
}

// Track close syscall
int trace_close(struct pt_regs *ctx, unsigned int fd) {
    if (fd <= 0) return 0;
    
    char op[] = "close";
    submit_event(ctx, fd, NULL, op);
    
    // Remove from our tracking map
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 pid_fd = ((u64)pid << 32) | fd;
    openfiles.delete(&pid_fd);
    
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

// Handle process exit to clean up our maps
int trace_exit_group(struct pt_regs *ctx, int error_code) {
    // We can't iterate through the map in BPF context,
    // so cleanup is handled in userspace
    return 0;
}
"""

# Load BPF program
try:
    b = BPF(text=bpf_text)
except Exception as e:
    print(f"Error loading BPF program: {e}")
    # Try with stack size option if available
    try:
        print("Retrying with increased stack size...")
        b = BPF(text=bpf_text, cflags=["-Wno-macro-redefined", "-Wno-incompatible-library-redeclaration", "-mllvm", "-bpf-stack-size=512"])
        print("Successfully loaded BPF program with increased stack size")
    except Exception as e:
        print(f"Error loading BPF program with increased stack size: {e}")
        print("Please ensure you have proper permissions to run BPF programs.")
        exit(1)

# User cache to avoid repeatedly looking up user names
user_cache = {}

# File descriptor cache for supplementing BPF tracking
# Format: {pid: {fd: filename}}
fd_cache = {}

# In-memory buffer to store events for later filtering
event_buffer = deque(maxlen=args.buffer_size)

# Function to attempt attaching probes with error handling
def attach_probe_safe(bpf_obj, event_type, event, fn_name):
    try:
        if event_type == "kprobe":
            bpf_obj.attach_kprobe(event=event, fn_name=fn_name)
        elif event_type == "kretprobe":
            bpf_obj.attach_kretprobe(event=event, fn_name=fn_name)
        print(f"Successfully attached {event_type} to {event}")
        return True
    except Exception as e:
        print(f"Warning: Failed to attach {event_type} to {event}: {e}")
        return False

# Attach to syscalls with both entry and return probes
# For open syscalls - we need both entry (for filename) and return (for fd)
attach_probe_safe(b, "kprobe", "sys_open", "trace_open_enter")
attach_probe_safe(b, "kprobe", "__x64_sys_open", "trace_open_enter")
attach_probe_safe(b, "kprobe", "do_sys_open", "trace_open_enter")

attach_probe_safe(b, "kretprobe", "sys_open", "trace_open_return")
attach_probe_safe(b, "kretprobe", "__x64_sys_open", "trace_open_return")
attach_probe_safe(b, "kretprobe", "do_sys_open", "trace_open_return")

# For openat syscalls
attach_probe_safe(b, "kprobe", "sys_openat", "trace_openat_enter")
attach_probe_safe(b, "kprobe", "__x64_sys_openat", "trace_openat_enter")
attach_probe_safe(b, "kprobe", "do_sys_openat", "trace_openat_enter")

attach_probe_safe(b, "kretprobe", "sys_openat", "trace_openat_return")
attach_probe_safe(b, "kretprobe", "__x64_sys_openat", "trace_openat_return")
attach_probe_safe(b, "kretprobe", "do_sys_openat", "trace_openat_return")

# For openat2 syscalls
attach_probe_safe(b, "kprobe", "sys_openat2", "trace_openat2_enter")
attach_probe_safe(b, "kprobe", "__x64_sys_openat2", "trace_openat2_enter")

attach_probe_safe(b, "kretprobe", "sys_openat2", "trace_openat2_return")
attach_probe_safe(b, "kretprobe", "__x64_sys_openat2", "trace_openat2_return")

# For write syscall
attach_probe_safe(b, "kprobe", "sys_write", "trace_write")
attach_probe_safe(b, "kprobe", "__x64_sys_write", "trace_write")
attach_probe_safe(b, "kprobe", "ksys_write", "trace_write")

# For close syscall
attach_probe_safe(b, "kprobe", "sys_close", "trace_close")
attach_probe_safe(b, "kprobe", "__x64_sys_close", "trace_close")
attach_probe_safe(b, "kprobe", "do_sys_close", "trace_close")

# For rename syscalls
attach_probe_safe(b, "kprobe", "sys_rename", "trace_rename")
attach_probe_safe(b, "kprobe", "__x64_sys_rename", "trace_rename")
attach_probe_safe(b, "kprobe", "do_sys_rename", "trace_rename")

attach_probe_safe(b, "kprobe", "sys_renameat", "trace_renameat")
attach_probe_safe(b, "kprobe", "__x64_sys_renameat", "trace_renameat")

attach_probe_safe(b, "kprobe", "sys_renameat2", "trace_renameat2")
attach_probe_safe(b, "kprobe", "__x64_sys_renameat2", "trace_renameat2")

# For unlink syscalls
attach_probe_safe(b, "kprobe", "sys_unlink", "trace_unlink")
attach_probe_safe(b, "kprobe", "__x64_sys_unlink", "trace_unlink")
attach_probe_safe(b, "kprobe", "do_unlinkat", "trace_unlink")

attach_probe_safe(b, "kprobe", "sys_unlinkat", "trace_unlinkat")
attach_probe_safe(b, "kprobe", "__x64_sys_unlinkat", "trace_unlinkat")

# For create/mkdir syscalls
attach_probe_safe(b, "kprobe", "sys_creat", "trace_creat")
attach_probe_safe(b, "kprobe", "__x64_sys_creat", "trace_creat")

attach_probe_safe(b, "kprobe", "sys_mkdir", "trace_mkdir")
attach_probe_safe(b, "kprobe", "__x64_sys_mkdir", "trace_mkdir")
attach_probe_safe(b, "kprobe", "do_mkdirat", "trace_mkdir")

attach_probe_safe(b, "kprobe", "sys_mkdirat", "trace_mkdirat")
attach_probe_safe(b, "kprobe", "__x64_sys_mkdirat", "trace_mkdirat")

# Track process exit for cleanup
attach_probe_safe(b, "kprobe", "sys_exit_group", "trace_exit_group")
attach_probe_safe(b, "kprobe", "__x64_sys_exit_group", "trace_exit_group")

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
        try:
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
        except ValueError:
            # Skip events with invalid timestamp format
            continue
    
    print(f"\nFound {match_count} matching events.")

# Signal handler for Ctrl+C - switches to command mode
def signal_handler(signal, frame):
    global in_command_mode
    in_command_mode = True
    print("\nSwitching to command mode...")

# Register the signal handler
signal.signal(signal.SIGINT, signal_handler)

# Improved FD resolution
def resolve_fd_to_filename(pid, fd):
    """Resolve a file descriptor to its filename using /proc"""
    # Check if process exists
    if not os.path.exists(f"/proc/{pid}"):
        return f"[unknown fd {fd} (process exited)]"
    
    # Use /proc/{pid}/fd/{fd} symlinks
    try:
        path = f"/proc/{pid}/fd/{fd}"
        if os.path.exists(path):
            filename = os.readlink(path)
            
            # Update our fd_cache
            if pid not in fd_cache:
                fd_cache[pid] = {}
            fd_cache[pid][fd] = filename
            
            return filename
    except (FileNotFoundError, PermissionError, OSError) as e:
        pass
    
    # Fall back to our fd_cache
    if pid in fd_cache and fd in fd_cache[pid]:
        return fd_cache[pid][fd]
    
    # Default fallback
    return f"[fd {fd}]"

# Clean up fd_cache
def cleanup_fd_cache():
    """Remove entries for processes that no longer exist"""
    for pid in list(fd_cache.keys()):
        if not os.path.exists(f"/proc/{pid}"):
            del fd_cache[pid]

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
    
    # For operations that don't directly provide filenames (write, close) or empty filename
    if (not filename or filename == "") and fd > 0:
        filename = resolve_fd_to_filename(pid, fd)
    
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

    # Periodically clean up our fd_cache (not on every event to avoid performance hit)
    if len(fd_cache) > 1000 or event.timestamp % 1000 == 0:
        cleanup_fd_cache()

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
        except Exception as e:
            print(f"Error processing command: {e}")

# Alternative command mode entry using keyboard input
def check_command_toggle():
    try:
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
    except Exception:
        # If there's any issue with terminal handling, just return False
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

# Main event loop with command mode support and error handling
try:
    continue_running = True
    last_check_time = time.time()
    last_cleanup_time = time.time()
    
    while continue_running:
        try:
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
                except Exception:
                    # If terminal input checking fails, fall back to signal-only
                    pass
            
            # Periodic cleanup of the fd_cache (every 60 seconds)
            if current_time - last_cleanup_time >= 60:
                last_cleanup_time = current_time
                cleanup_fd_cache()
                
        except KeyboardInterrupt:
            # Handle KeyboardInterrupt (Ctrl+C) to enter command mode
            in_command_mode = True
            print("\nSwitching to command mode...")
            continue_running = command_mode()
        except Exception as e:
            # Handle any other exceptions gracefully
            print(f"Error in main loop: {e}")
            time.sleep(1)  # Prevent tight loop if errors are persistent
                
except KeyboardInterrupt:
    print("\nExiting program...")
finally:
    # Clean up any resources
    print("Cleaning up resources...")
    # BPF automatically cleans up when the program ends