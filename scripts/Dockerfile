FROM alpine:latest

# installing strace
RUN apk add --no-cache strace

# Create user and home directory
RUN adduser -u 2001 -D -h /home/testuser testuser

# Switch to new user
USER testuser
WORKDIR /home/testuser

# Default command
CMD ["sleep", "infinity"]
