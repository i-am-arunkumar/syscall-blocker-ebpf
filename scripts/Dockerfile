FROM alpine:latest

# Install shadow (optional, for advanced user management)
#RUN apk add --no-cache shadow

# Create user and home directory
RUN adduser -u 2001 -D -h /home/testuser testuser

# Switch to new user
USER testuser
WORKDIR /home/testuser

# Default command
CMD ["sleep", "infinity"]
