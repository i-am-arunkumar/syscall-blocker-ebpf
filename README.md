# System Call Blocker

## **Objective**
The goal of this assignment is to design a tool that can **block specific system calls** when triggered by certain users or **mount namespace IDs**. This can be useful for security, monitoring, or sandboxing environments.

## **Repository Setup**
1. **Clone the repository:**
   ```sh
   git clone <repo-link>
   cd syscall-blocker
   # update submodules   
   ```
2. **Update submodules**
   ```sh
   git submodule update --init --recursive
   ```
## **Implementation details**
The syscall_blocker eBPF source is a kernel probe program, which attaches to the target system-call kprobe function for observing, e.g., "__x64_sys_mkdir" and filtering the syscalls initiated by the target users and mount namespaces. The kprobe program can inject errors into the target syscall by tampering with the syscall's return value. This approach throws errors to the users affected. Tracepoint ebpf programs can only observe the raw syscalls and cannot block a system call. Hence, kprobe is a suitable approach to block syscalls. The more efficient way could be using seccomp filters directly in the eBPF program (https://arxiv.org/abs/2302.10366), but it is still a debate to add seccom to ebpf for various reasons mentioned in the article https://lwn.net/Articles/857228/. 
The source files are in the `src` directory. eBPF program is implemented in `syscall_blocker.bpf.c`, and the user space program is implemented in `syscall_blocker.c`. Common definitions between the ebpf program and the user program, such as configuration and events, are defined in the `syscall_blocker.h` header file. The configuration is passed on to the bpf program using a map array, and the events stream containing vital information for logging blocked syscalls by the bpf program is streamed through ring buffers to the user program, in which it can poll the events. The configuration is a static structure that contains syscalls, uids, and mount namespace ids to block, which are passed as command line arguments from the user. The events from the bpf program are polled and printed as logs in the user space program. The program can be exited either by pressing `esc` key or passing SIGINT or SIGTERM signals (could be used to terminate the user program cleanly in testing scripts).  

Additionally, using the cgroup path, the process's container could be identified if the process is containerized. In the case of a docker container, the first 12 characters available cgroup path is the shortened container id, which could be used to kill the container via docker CLI. The prompt to kill a container can be started by pressing the `k` key on the keyboard.

## **Repository Structure**
```
/ (Root)
│── README.md          # Detailed assignment instructions
│── Makefile           # Build and run commands
│── src/
│   │── syscall_blocker.c         # User-space control program
│   │── syscall_blocker.bpf.c     # eBPF program to intercept syscalls
|   |── syscall_blocker.h         # definitions for common data structures.
│── scripts/
│   │── test.sh        # Script to test the program
|   |── Dockerfile     # Docker defines the alpine image for testing
```

## Dependencies
The user space program depends on libbpf and bpftool as main dependencies, and these libraries are available as submodules in this repository. Hence, the libbpf and bpftool are built as dependencies for the syscall blocker program. Additionally, libseccomp is required as dependency, providing API functions to resolve syscall numbers and names. libseccomp can be installed system-wide by the distros package manager, eg. `sudo apt install libseccomp-dev` (ubuntu). 
libbpf is the user space library required to interface with the ebpf module in the kernel. bpftool is used to generate the bpf skeleton template, which exposes the program-specific interfaces to load and manage the ebpf program; this enables the shipping of the ebpf program to any user program. bpftool is also used to generate vmlinux.h file has definitions of kernel data structures where the program is built.

## **Building**
This project uses Makefile to build  the source program and its libraries. Executing `make` in the root path will build the libraries, and generate skeleton files, vmlinux.h file and syscall_block executable program. 
```
make
```
## Usage and example
The executable file accepts `--help` as argument and prints the available options. The syscall names, user IDs, and mount namespace IDs are mandatory arguments for this program. The  `--traceonly` argument is optional and adding this argument attach the ebpf program to tracepoint (tracepoint/raw_syscalls/sys_enter) rather than kprobe functions (__x64_sys_<syscall_name>) (kprobe is default). eBPF program attached to Tracepoints can only observe the system calls but cannot block them, but a kprobe program can at least inject error into the syscall to make it unusable.
```sh
"Usage: sudo ./syscall_blocker --users <user ids> --mntnss <mount namspace ids> --syscalls <syscall names> "
      "blocks system calls."
      "The available options:\n\n"
      "--syscalls     syscall names to intercept\n"
      "--users        user ids to filter\n"
      "--mntnss       mount namespace ids to filter\n"
      "--traceonly    attach only tracepoint (can't block syscall),"
```
Blocking vulnerable syscalls such as write or read could affect the host system. A testing mount namespace can be created using the `sudo unshare -m` command and the mount namespace ID obtained (`stat -L -c %i /proc/self/ns/mnt`). Only the commands executed in the shell started by unshare command are affected if we use its mount namespace, as it uses a different mount namespace rather than the host system's mount namespace.
**Example :**
The following example blocks `mkdir` and `geteuid` system calls initiated by users with id 2000 or 2001 or initiated in the mount namespace with 4026532739.
```sh
sudo ./syscall_blocker --syscalls mkdir --users 2000 2001 --mntnss 4026532739
```
**Output of the above example:**
```
bpf program has been loaded and verified.
Configuration written to BPF map: 
UIDs=2000 2001
MNT_NS_IDs=4026532739 
SYSCALL_NOs=83 107 
eBPF kprobe program has been attached to the syscall function __x64_sys_mkdir.
eBPF kprobe program has been attached to the syscall function __x64_sys_geteuid.
eBPF program loaded and attached.
Press : k - kill container, esc -  Exit

Event : Blocked syscall mkdir initiated by PID 270281 (mkdir) - container = d8b47427b1b2 (docker) UID=2001 MNTNS_ID=4026532739.
Event : Blocked syscall geteuid initiated by PID 270321 (whoami) - container = d8b47427b1b2 (docker) UID=2001 MNTNS_ID=4026532739.
Exiting...

```
## Listing Docker containers and kill it.
The syscall_blocker also queries the cgroup path of each syscall filtered to identify the container it was invoked, usually cgroup path of docker container will be `docker-<container-id>`, hence by using this pattern, we can tell whether the syscall intercepted was from a process in a docker (or podman) container or a host system. Usually, docker uses a different mount namespace rather than the host system's namespace. The events from the ebpf include the group path obtained from the blocked syscall, and the user program decodes the path to identify the container type (docker or postman) and the container id. Further, this container ID could be used to kill the container using the docker (or postman) cli by the command `docker kills container_id.` The user program provides a prompt to do this within the program itself by pressing the `k` key; the program asks for the container ID and the container type, which is found in the event logs in the program itself. The program executes the container kill api of the docker (or podman) to kill that container
## **Testing**
Testing script `./test.sh` is in the directory scripts. There is a Dockerfile that defines an alpine image with a user with id 2001 and installs strace utility to trace syscalls in the same scripts. The script uses the Dockerfile to run a test docker container and tries to execute the `mkdir` syscall and `geteuid` syscall by using commands such as `mkdir` and `whoami.` and checks the syscall traces of these commands and expects the return value of the syscall as -1 (EACCES - permission denied). If the syscalls throw an error (EACCES), then the test case is considered as passed. Execute the test.sh script in the directory where the Dockerfile is present (`cd ./scripts`).
**Output of test script :**
```
TEST CASE 1 : block mkdir and geteuid invoked by any process from a docker container
========
Starting docker
DEPRECATED: The legacy builder is deprecated and will be removed in a future release.
            Install the buildx component to build images with BuildKit:
            https://docs.docker.com/go/buildx/

Sending build context to Docker daemon  6.656kB
Step 1/6 : FROM alpine:latest
 ---> aded1e1a5b37
Step 2/6 : RUN apk add --no-cache strace
 ---> Using cache
 ---> 27e8a384071c
Step 3/6 : RUN adduser -u 2001 -D -h /home/testuser testuser
 ---> Using cache
 ---> 4fb0cf0abf71
Step 4/6 : USER testuser
 ---> Using cache
 ---> a7577901108b
Step 5/6 : WORKDIR /home/testuser
 ---> Using cache
 ---> eaa0fc9c4e62
Step 6/6 : CMD ["sleep", "infinity"]
 ---> Using cache
 ---> 6897fef13493
Successfully built 6897fef13493
Successfully tagged test_user_profile:latest
b908ba6630e2062f883036f601473678df89ce0005dd1f7610b19eb0489fb133
Container PID: 310164
Mount Namespace ID of the container: 4026537481
User ID: 2001
Running in sudo mode
Loading the eBPF program...
syscall_blocker started with pid 310256
Invoking the system calls in the container...
Trace of mkdir :
mkdir("newdir", 0777) = -1 EACCES (Permission denied) mkdir: can't create directory 'newdir': Permission denied +++ exited with 1 +++
Trace of whoami :
geteuid() = -1 EACCES (Permission denied) whoami: unknown uid 4294967283 +++ exited with 1 +++
TEST CASE PASSED : mkdir blocked with error: EACCES
TEST CASE PASSED : geteuid blocked with error: EACCES
output of syscall_blocker is written to syscall_blocker.log
Stopping and removing the container...
test-container
test-container
```
