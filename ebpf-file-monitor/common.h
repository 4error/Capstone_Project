#ifndef __COMMON_H
#define __COMMON_H

#define TASK_COMM_LEN 16
#define MAX_PATH_LEN  256

// Enum to identify the traced function. Renamed to avoid kernel conflicts.
enum fs_op_type {
    FS_OP_UNKNOWN,
    FS_OP_CLOSE,
    FS_OP_SYNC,
    FS_OP_WRITEV,
    FS_OP_SPLICE,
    FS_OP_TRUNCATE,
    FS_OP_RENAME,
};

struct event {
    __u32 pid;
    __u32 ppid;
    __u64 mnt_ns_id;
    char comm[TASK_COMM_LEN];
    enum fs_op_type op;
    int ret;
    char path[MAX_PATH_LEN];
    char old_path[MAX_PATH_LEN];
};

#endif /* __COMMON_H */