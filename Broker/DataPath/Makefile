TARGET = main
BPF_OBJ = $(TARGET).o
BPF_SRC = $(TARGET).c

INTERFACE ?= lo

CLANG = clang
CFLAGS = -O2 -target bpf -g

.PHONY: all clean load unload reload

all: $(BPF_OBJ)

$(BPF_OBJ): $(BPF_SRC)
	$(CLANG) $(CFLAGS) -c $< -o $@

load: $(BPF_OBJ)
	sudo ip link set dev $(INTERFACE) xdp obj $(BPF_OBJ) sec xdp

unload:
	sudo ip link set dev $(INTERFACE) xdp off

reload: unload load

clean:
	rm -f $(BPF_OBJ)