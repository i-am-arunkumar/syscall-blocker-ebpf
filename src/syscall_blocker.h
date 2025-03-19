// This file contains definitions common to ebpf and the user-space program.


// definition for the configurations from user program to ebpf program.

#define MAX_ENTRIES 5

struct Configuration {
  unsigned long uids[MAX_ENTRIES];  
  unsigned long mntns_ids[MAX_ENTRIES];
  int syscall_nums[MAX_ENTRIES];
  int count_uids;
  int count_mntns;
  int count_syscalls;
};

// definition for the events passed from ebpf program to the user program
struct event {
  char container_id[64];
  int pid;
  char comm[16];
};
