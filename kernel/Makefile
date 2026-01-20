# LinusWare Kernel Module Build
obj-m += linusware.o

# Additional CFLAGS for the module
ccflags-y := -DDEBUG -g -Wall

# Multi-file module (if we add more source files)
# linusware-objs := linusware.o inject.o netlink.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

install:
	sudo insmod linusware.ko
	sudo chmod 666 /dev/linusware

remove:
	sudo rmmod linusware

reload: remove install

status:
	@lsmod | grep linusware || echo "Module not loaded"
	@ls -la /dev/linusware 2>/dev/null || echo "Device not found"
	@dmesg | tail -20 | grep linusware || true
