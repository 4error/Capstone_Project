// monitor.bpf.c (Final Version for Kernel 5.15 and older)

// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

#define FMODE_WRITTEN 0x80
#define MAX_PATH_COMPONENTS 20 // Bounded loop limit

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

char LICENSE[] SEC("license") = "GPL";

// --- Manual Path Traversal for Kernels < 5.18 ---
static __always_inline int get_path(struct path *path, char *buf, u32 size) {
    if (size <= 1) return -1;

    // Prepare buffer by null-terminating the end
    buf[size - 1] = 0;
    int buf_off = size - 1;

    struct dentry *dentry = BPF_CORE_READ(path, dentry);
    struct vfsmount *vfsmnt = BPF_CORE_READ(path, mnt);
    struct mount *mount = container_of(vfsmnt, struct mount, mnt);
    struct dentry *mnt_root;
    struct mount *parent_mount;
    
    mnt_root = BPF_CORE_READ(mount, mnt_root);
    parent_mount = BPF_CORE_READ(mount, mnt_parent);

    // Climb up the dentry tree within the current mount
    #pragma unroll
    for (int i = 0; i < MAX_PATH_COMPONENTS; i++) {
        if (dentry == mnt_root || dentry == BPF_CORE_READ(dentry, d_parent)) {
            break;
        }

        int len = BPF_CORE_READ(dentry, d_name.len);
        if (len <= 0 || len >= (MAX_PATH_LEN -1)) break;

        buf_off -= len;
        if (buf_off < 0) return -1;
        BPF_CORE_READ_STR_INTO(&buf[buf_off], dentry, d_name.name, len + 1);

        buf_off--;
        if (buf_off < 0) return -1;
        buf[buf_off] = '/';

        dentry = BPF_CORE_READ(dentry, d_parent);
    }
    
    // Climb up the mount tree
    #pragma unroll
    for (int i = 0; i < MAX_PATH_COMPONENTS; i++) {
        if (mount == parent_mount) break; // Reached root mount

        dentry = BPF_CORE_READ(mount, mnt_mountpoint);
        mount = BPF_CORE_READ(mount, mnt_parent);
        parent_mount = BPF_CORE_READ(mount, mnt_parent);
        
        int len = BPF_CORE_READ(dentry, d_name.len);
        if (len <= 0 || len >= (MAX_PATH_LEN -1)) break;
        
        buf_off -= len;
        if (buf_off < 0) return -1;
        BPF_CORE_READ_STR_INTO(&buf[buf_off], dentry, d_name.name, len + 1);

        buf_off--;
        if (buf_off < 0) return -1;
        buf[buf_off] = '/';
    }

    if (buf_off == size - 1) { // Path is empty, must be root '/'
        buf_off--;
        buf[buf_off] = '/';
    }
    
    // Move the constructed path to the beginning of the buffer
    int path_len = size - buf_off;
    bpf_probe_read_kernel(buf, path_len, &buf[buf_off]);
    buf[path_len] = 0;

    return 0;
}

static __always_inline void submit_generic_event(struct pt_regs *ctx, enum fs_op_type op, struct file *file, int ret) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u64 id = bpf_get_current_pid_tgid();
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return;

    e->pid = id >> 32;
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    e->mnt_ns_id = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->op = op;
    e->ret = ret;
    e->old_path[0] = 0;
    get_path(&file->f_path, e->path, sizeof(e->path));
    bpf_ringbuf_submit(e, 0);
}

/* KPROBES */

SEC("kretprobe/filp_close")
int filp_close_exit(struct pt_regs *ctx) {
    int ret = PT_REGS_RC(ctx);
    struct file *file = (struct file *)PT_REGS_PARM1(ctx);
    if (ret != 0 || !(BPF_CORE_READ(file, f_mode) & FMODE_WRITTEN)) return 0;
    submit_generic_event(ctx, FS_OP_CLOSE, file, ret);
    return 0;
}

SEC("kprobe/vfs_sync_range")
int vfs_sync_range_entry(struct pt_regs *ctx) {
    struct file *file = (struct file *)PT_REGS_PARM1(ctx);
    submit_generic_event(ctx, FS_OP_SYNC, file, 0);
    return 0;
}

SEC("kretprobe/vfs_writev")
int vfs_writev_exit(struct pt_regs *ctx) {
    int ret = PT_REGS_RC(ctx);
    if (ret <= 0) return 0;
    struct file *file = (struct file *)PT_REGS_PARM1(ctx);
    submit_generic_event(ctx, FS_OP_WRITEV, file, ret);
    return 0;
}

SEC("kprobe/do_splice_from")
int do_splice_from_entry(struct pt_regs *ctx) {
    struct file *out = (struct file *)PT_REGS_PARM2(ctx);
    submit_generic_event(ctx, FS_OP_SPLICE, out, 0);
    return 0;
}

SEC("kprobe/vfs_truncate")
int vfs_truncate_entry(struct pt_regs *ctx) {
    const struct path *path = (const struct path *)PT_REGS_PARM1(ctx);
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    e->mnt_ns_id = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->op = FS_OP_TRUNCATE;
    e->ret = 0;
    e->old_path[0] = 0;
    get_path((struct path *)path, e->path, sizeof(e->path));
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/vfs_rename")
int vfs_rename_entry(struct pt_regs *ctx) {
    struct dentry *old_dentry = (struct dentry *)PT_REGS_PARM3(ctx);
    struct dentry *new_dentry = (struct dentry *)PT_REGS_PARM5(ctx);
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    e->mnt_ns_id = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->op = FS_OP_RENAME;
    e->ret = 0;
    struct path old_path = {}, new_path = {};
    old_path.dentry = old_dentry;
    new_path.dentry = new_dentry;
    struct nsproxy *ns = BPF_CORE_READ(task, nsproxy);
    struct mnt_namespace *mnt_ns = BPF_CORE_READ(ns, mnt_ns);
    struct mount *root_mount = BPF_CORE_READ(mnt_ns, root);
    struct vfsmount *mnt = &root_mount->mnt;
    old_path.mnt = mnt;
    new_path.mnt = mnt;
    get_path(&old_path, e->old_path, sizeof(e->old_path));
    get_path(&new_path, e->path, sizeof(e->path));
    bpf_ringbuf_submit(e, 0);
    return 0;
}