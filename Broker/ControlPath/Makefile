CC = gcc
CFLAGS = -O2 -Wall
LDLIBS = -lbpf
TARGET = xdp_manual
OBJS = main.o bpf_syscalls.o

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS) $(LDLIBS)

main.o: main.c bpf_syscalls.h
	$(CC) $(CFLAGS) -c main.c

bpf_syscalls.o: bpf_syscalls.c bpf_syscalls.h
	$(CC) $(CFLAGS) -c bpf_syscalls.c

clean:
	rm -f *.o $(TARGET)