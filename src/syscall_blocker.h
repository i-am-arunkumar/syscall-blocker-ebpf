// This file contains definitions common to ebpf and the user-space program.


// definition for the configurations from user program to ebpf program.

#define MAX_ENTRIES 5
#define CONTAINER_ID_LEN 65
#define MAX_CGROUP_LEN 100

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
  char cgroup_path[100];
  int pid;
  int uid;
  unsigned long mntns_id;
  int syscall_no;
  char comm[16];
};
