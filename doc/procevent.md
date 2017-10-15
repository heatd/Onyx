# Process events
Onyx implements a process event interface for processes to recieve, listen and poll
for events in other processes; such events can include syscalls, page faults, 
I/O operations, etc.

## Interface

``` #include <onyx/proc_event.h>

int proc_event_attach(pid_t pid, unsigned long flags);
```

`proc_event_attach()` attaches the current process to the `pid` and returns a file
descriptor that represents the connection between the calling process and the
target process. Currently, `proc_event_attach()` uses the following flags:

* `PROC_EVENT_LISTEN_SYSCALLS		0x000000000000001`

Currently, the returned file descriptor implements the following operations:

* read
* ioctl

### Ioctls

* `PROCEVENT_ACK` - Acknowledges the event, allowing the target program to proceed

## Example usage

```
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

#include <onyx/proc_event.h>

int main(int argc, char **argv, char **envp)
{
	pid_t target_pid = 1;
	int fd = proc_event_attach(target_pid, PROC_EVENT);
	if(fd < 0)
	{
		perror("proc_event_attach");
		return 1;
	}

	struct proc_event_syscall syscall_context;

	while(read(fd, &syscall_context, sizeof(struct proc_event_syscall)))
	{
		printf("System call number %u\n", syscall_context.nr_syscall);
		ioctl(fd, PROCEVENT_ACK);
	}
}

```
