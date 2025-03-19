// filepath: /sys-call-blocker/src/syscall_blocker.bpf.c

// trace logs : $ sudo cat /sys/kernel/debug/tracing/trace_pipe

#include "syscall_blocker.h"
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <errno.h>

// Define a BPF map to pass configurations to ebpf program
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, int);
  __type(value, struct Configuration);
} block_syscall_map SEC(".maps");

// Define a BPF ring buffer to stream the list of containers to user space
// program
/* struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024);
} events SEC(".maps");

 */
/**
 * This kprobe program  is attached to the desired syscalls in user space
 * program. It matches the current user id or mount namespace id with the ids
 * found in the configuration passed from the user-space program. It uses the
 * bpf_override_return helper function to set error return code, in case there
 * is a match in the filter
 */
SEC("kprobe")
int block_syscall(struct pt_regs *ctx) {

  struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();

  uid_t uid = (uid_t)(bpf_get_current_uid_gid() & 0xFFFFFFFF);
  unsigned long mnt_ns = task->nsproxy->mnt_ns->ns.inum;

  int key = 0;
  struct Configuration *config = bpf_map_lookup_elem(&block_syscall_map, &key);

  if (!config) {
    bpf_printk("syscall blocker: No configuration found in BPF map\n");
    return 1;
  }

  // filter by user ids and mount namespace ids.
  int max = config->count_mntns;
  if (config->count_uids > max) {
    int max = config->count_uids;
  }

  for (int i = 0; i < max; i++) {
    if ((i < MAX_ENTRIES && uid == config->uids[i]) ||
        (i < MAX_ENTRIES && mnt_ns == config->mntns_ids[i])) {
      u32 pid = bpf_get_current_pid_tgid() >> 32;
      bpf_printk("PID : %lu - syscall blocked through kprobe: UID - %lu and "
                 "MNT_NS id - %lu\n",
                 pid, uid, mnt_ns);
      bpf_override_return(ctx, EACCES); // inject error to block the syscall
      return 0;
    }
  }

  return 0;
}

/**
 * This is tracing point and can only trace syscall, cannot do more than logging
 * kernel ignores the return value of this program
 */
SEC("tracepoint/raw_syscalls/sys_enter")
int trace_syscall(struct trace_event_raw_sys_enter *ctx) {

  unsigned int syscall_id = ctx->id;

  struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();

  uid_t uid = task->cred->uid.val;
  unsigned long mnt_ns = task->nsproxy->mnt_ns->ns.inum;

  int key = 0;
  struct Configuration *config = bpf_map_lookup_elem(&block_syscall_map, &key);

  if (!config) {
    bpf_printk("syscall blocker: No configuration found in BPF map\n");
    return 1;
  }

  // check if it is the target syscall
  bool is_target = false;
  for (int i = 0; i < config->count_syscalls && i < MAX_ENTRIES; i++) {
    if (syscall_id == config->syscall_nums[i]) {
      is_target = true;
      break;
    }
  }

  if (!is_target) {
    return 0;
  }

  int max_idx = config->count_mntns;
  if (config->count_uids > max_idx) {
    int max = config->count_uids;
  }

  for (int i = 0; i < max_idx; i++) {
    if ((i < MAX_ENTRIES && uid == config->uids[i]) ||
        (i < MAX_ENTRIES && mnt_ns == config->mntns_ids[i])) {
      u32 pid = bpf_get_current_pid_tgid() >> 32;
      bpf_printk(
          "PID : %lu - syscall %d detected in tracepoint -  UID : %d and "
          "MNT_NS : %lu\n",
          pid, syscall_id, uid, mnt_ns);
      return 0;
    }
  }

  return 0;
}

char _license[] SEC("license") = "GPL";