CC = clang
CFLAGS = -O2 -Wall -target bpf -g -I/usr/include/$(shell uname -m)-linux-gnu
TARGET = main.o

INTERFACE ?= lo

all: $(TARGET)

$(TARGET): main.c
	$(CC) $(CFLAGS) -c main.c -o $(TARGET)

load: $(TARGET)
	sudo ip link set dev $(INTERFACE) xdp obj $(TARGET) sec xdp

unload:
	sudo ip link set dev $(INTERFACE) xdp off

reload: unload load

clean:
	rm -f *.o

.PHONY: all clean load unload reload