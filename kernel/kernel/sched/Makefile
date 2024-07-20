sched-y:= mutex.o scheduler.o rwlock.o wait.o

obj-y+= $(patsubst %, kernel/sched/%, $(sched-y))

kernel/sched/scheduler.o: include/onyx/gen/trace_sched.h
