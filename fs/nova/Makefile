#
# Makefile for the linux NOVA filesystem routines.
#

obj-m += nova.o

nova-y := balloc.o bbuild.o bdev.o profile.o migration.o vpmem.o sysfs.o\
		checksum.o dax.o dir.o file.o gc.o inode.o \
		ioctl.o journal.o log.o mprotect.o namei.o parity.o \
		rebuild.o snapshot.o stats.o super.o symlink.o perf.o 

all:
	make -C /lib/modules/$(shell uname -r)/build M=`pwd`

clean:
	make -C /lib/modules/$(shell uname -r)/build M=`pwd` clean
