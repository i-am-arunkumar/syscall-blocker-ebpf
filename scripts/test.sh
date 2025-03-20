#!/bin/bash

# This script is a placeholder for testing the blocking functionality.
# Add your test cases here.

CONTAINER_NAME="test-container"
IMAGE="alpine" # possibly smallest container

if [ "$EUID" -ne 0 ]; then
    echo "Switching to sudo mode..."
    exec sudo bash "$0" "$@"
fi

echo "TEST CASE 1 : block mkdir and geteuid invoked by any process from a docker container"
echo "========"
# Run a Docker container
echo "Starting docker"
docker build -t test_user_profile .
docker run -d --name $CONTAINER_NAME test_user_profile 

# Get the container's PID
CONTAINER_PID=$(docker inspect -f '{{.State.Pid}}' $CONTAINER_NAME)
echo "Container PID: $CONTAINER_PID"

# Get the mount namespace ID
MOUNT_NS_ID=$(sudo stat -L -c %i /proc/$CONTAINER_PID/ns/mnt)
echo "Mount Namespace ID of the container: $MOUNT_NS_ID"

# Get the user ID
USER_ID=$(awk '/^Uid:/ {print $2}' /proc/$CONTAINER_PID/status)
echo "User ID: $USER_ID"

# Load the eBPF program
rm -f syscall_blocker.log

# Now the script runs as root
echo "Running in sudo mode"

echo "Loading the eBPF program..."
sudo ../syscall_blocker --syscalls mkdir geteuid --users  $USER_ID  --mntnss $MOUNT_NS_ID > syscall_blocker.log &
SYSCALL_BLOCKER_PID=$!

echo "syscall_blocker started with pid $SYSCALL_BLOCKER_PID"
sleep 2
# Test the system call in the container
echo "Invoking the system calls in the container..."
mkdirout=$(docker exec $CONTAINER_NAME sh -c "strace -e trace=mkdir mkdir newdir" 2>&1)
whoamiout=$(docker exec $CONTAINER_NAME sh -c "strace -e trace=geteuid whoami" 2>&1)

echo "Trace of mkdir : "
echo $mkdirout


echo "Trace of whoami : "
echo $whoamiout


if [[ "$mkdirout" =~ "= -1" ]]; then
    error_code=$(echo "$mkdirout" | awk 'NR==1 {print $(NF-2)}')
    echo "TEST CASE PASSED : mkdir blocked with error: $error_code"
else
    echo "TEST CASE FAILED : mkdir was not blocked."
fi

if echo "$whoamiout" | grep -q '= -1'; then
    error_code=$(echo "$whoamiout" | awk 'NR==1 {print $(NF-2)}')
    echo "TEST CASE PASSED : geteuid blocked with error: $error_code"
else
    echo "TEST CASE FAILED : geteuid was not blocked."
fi

sleep 5
#kill -SIGTERM $SYSCALL_BLOCKER_PID

sudo killall -SIGTERM -q syscall_blocker
echo "output of syscall_blocker is written to syscall_blocker.log"

# Clean up
echo "Stopping and removing the container..."
docker stop $CONTAINER_NAME
docker rm $CONTAINER_NAME