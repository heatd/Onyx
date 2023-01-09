fs-y:= block.o dentry.o dev.o file.o null.o pagecache.o partition.o pipe.o poll.o pseudo.o \
	superblock.o sysfs.o tmpfs.o vfs.o zero.o buffer.o inode.o

include kernel/fs/ext4/Makefile

obj-y+= $(patsubst %, kernel/fs/%, $(fs-y))
