#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct data_t
{
    u32 uid;
    char comm[TASK_COMM_LEN];
    char fname[256];
    int flags;
};

BPF_PERF_OUTPUT(events);

int syscall__openat(struct pt_regs *ctx, int dfd, const char __user *filename, int flags)
{
    u32 uid = bpf_get_current_uid_gid();

    struct data_t data = {};
    data.uid = uid;
    data.flags = flags;

    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.fname, sizeof(data.fname), (void *)filename);

    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}