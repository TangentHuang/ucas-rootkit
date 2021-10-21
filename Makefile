obj-m := rootkitCD.o
all:
	make -C  "/lib/modules/$(shell uname --release)/build" M="$(shell pwd)"
clean:
	make -C "/lib/modules/$(shell uname --release)/build" M="$(shell pwd)"
