#include <string.h>
#include <stdio.h>
#include <unistd.h>

int file = 0;
char buffer[0x1000];
int main(int argc, char **argv)
{
	write(STDOUT_FILENO, "cat", 3);
	int fd = open(argv[1], 0);
	file = fd;
	unsigned long size = lseek(fd, 0, SEEK_END);
	lseek(fd, 0, SEEK_SET);
	read(fd, &buffer, size);
	write(STDOUT_FILENO, &buffer, size);
	int c;
	char *args[] = {"Hello World!", NULL};
	fork();
	write(STDOUT_FILENO, "If you're reading this, fork worked\n", strlen("If you're reading this, fork worked\n"));
	posix_spawn(&c, "/bin/echo", NULL, NULL, args, NULL);
	write(STDOUT_FILENO, "Spawned /bin/echo!", strlen("Spawned /bin/echo!"));
	return 0;
}
