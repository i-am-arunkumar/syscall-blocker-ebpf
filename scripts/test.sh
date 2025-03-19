#!/bin/bash

# This script is a placeholder for testing the blocking functionality.
# Add your test cases here.

CONTAINER_NAME="test-container"
IMAGE="alpine" # possibly smallest container

#TEST CASE 1 : block write system call

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
# echo "Loading the eBPF program..."
# sudo ./syscall_blocker --syscalls write --users  --mntnss $MOUNT_NS_ID

# # Test the system call in the container
# echo "Testing the system call in the container..."
# docker exec -it $CONTAINER_NAME sh -c "strace -e trace=open touch /tmp/testfile.txt"

# # Clean up
# echo "Stopping and removing the container..."
# docker stop $CONTAINER_NAME
# docker rm $CONTAINER_NAME