fs-y:= anon_inode.o block.o dentry.o dev.o file.o null.o partition.o pipe.o poll.o pseudo.o \
	superblock.o sysfs.o tmpfs.o vfs.o zero.o buffer.o inode.o namei.o filemap.o writeback.o

include kernel/fs/ext2/Makefile
include kernel/fs/block/Makefile

include/onyx/gen/trace_%.h: trace/trace_$*.json trace/gentrace.py
	python3 trace/gentrace.py $< include/onyx/gen/trace_$*.h kernel/fs/$*.trace.cpp

kernel/fs/%.trace.cpp: trace/trace_%.json trace/gentrace.py
	python3 trace/gentrace.py $< include/onyx/gen/trace_$*.h kernel/fs/$*.trace.cpp

kernel/fs/vfs.o: include/onyx/gen/trace_writeback.h

kernel/fs/filemap.o: include/onyx/gen/trace_filemap.h

kernel/fs/dentry.o: include/onyx/gen/trace_dentry.h

fs-y+= writeback.trace.o filemap.trace.o dentry.trace.o

obj-y+= $(patsubst %, kernel/fs/%, $(fs-y))
