KERNEL_MODULE = rkm
KERNEL = $(shell uname -r)
KERNEL_BUILD = /usr/lib/modules/$(KERNEL)/build

TRIPLE = x86_64-unknown-none-gnu
CARGO = $(shell which cargo)
BUILD = rustc --release $(RFLAGS) -- --emit obj -C code-model=kernel -C relocation-model=static -C no-redzone=y

obj-m += $(KERNEL_MODULE).o
$(KERNEL_MODULE)-objs := $(KERNEL_MODULE)-build.o target/release/$(KERNEL_MODULE).o

all:
	$(CARGO) $(BUILD)
	make -C $(KERNEL_BUILD) M=$(CURDIR) modules

clean:
	$(CARGO) clean
	make -C $(KERNEL_BUILD) M=$(CURDIR) clean
	rm *.c
