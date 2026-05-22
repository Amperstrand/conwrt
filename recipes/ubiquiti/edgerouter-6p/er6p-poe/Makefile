# er6p-poe out-of-tree build
# Usage: make -C <sdk_path> M=$(PWD) modules

ifneq ($(KERNELRELEASE),)
include $(src)/Kbuild
else
KDIR ?= /lib/modules/$(shell uname -r)/build

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
endif
