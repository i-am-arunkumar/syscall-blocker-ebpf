# Makefile

CC = gcc
CFLAGS = -Wall -Wextra -O2
BPF_CFLAGS = -I/usr/include/bpf -I/usr/include/linux
BPF_PROG = bpf_prog.o
TARGET = main

all: $(TARGET)

$(TARGET): src/main.o $(BPF_PROG)
	$(CC) $(CFLAGS) -o $(TARGET) src/main.o $(BPF_PROG) -lelf -lbpf

src/main.o: src/main.c
	$(CC) $(CFLAGS) -c src/main.c

$(BPF_PROG): src/bpf_prog.c
	$(CC) $(BPF_CFLAGS) -c src/bpf_prog.c -o $(BPF_PROG)

clean:
	rm -f $(TARGET) src/*.o $(BPF_PROG)

.PHONY: all clean