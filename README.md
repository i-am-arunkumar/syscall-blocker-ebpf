# System Call Blocker

## **Objective**
The goal of this assignment is to design a tool that can **block specific system calls** when triggered by certain users or **mount namespace IDs**. This can be useful for security, monitoring, or sandboxing environments.

## **Repository Setup**
1. **Clone the repository:**
   ```sh
   git clone <repo-link>
   cd syscall-blocker
   ```
2. **Modify and extend the provided template** according to the requirements.

## **Implementation Details**
- Use **eBPF** to intercept system calls at the kernel level.
- Implement filtering based on:
  - **User IDs** (UIDs)
  - **Mount namespace IDs**
- Allow users to specify which system calls should be blocked.
- Provide **logging** for blocked system calls.
- Extend functionality to:
  - List running containers (Docker, Podman, etc.).
  - Kill selected containers.
- Implement user-space control using **libbpf, BCC, or Go eBPF**.

## **Documentation Requirements**
Your submission must include:
- A **README.md** file with:
  - Clear setup and installation instructions
  - Usage examples and command-line arguments
  - Required dependencies and supported versions
- Well-documented code with meaningful comments.
- A script (`scripts/test.sh`) to test the blocking functionality.

## **Repository Structure**
```
/ (Root)
│── README.md          # Detailed assignment instructions
│── Makefile           # Build and run commands
│── src/
│   │── main.c         # User-space control program
│   │── bpf_prog.c     # eBPF program to intercept syscalls
│── scripts/
│   │── test.sh        # Script to test the program
```

## **Submission Instructions**
1. Complete your implementation and ensure it meets the assignment requirements.
2. Update the `README.md` with detailed instructions on how to build and run your solution.
3. **Make a pull request (PR)** to submit your final code.
4. Your PR should include:
   - A description of your implementation.
   - Any limitations or known issues.
   - Example test cases demonstrating blocked system calls.

**Happy coding! 🚀**