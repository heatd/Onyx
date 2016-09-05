#include <string.h>
#include <stdio.h>
#include <unistd.h>

int file = 0;
char buffer[0x1000];
int main(int argc, char **argv)
{
	write(STDOUT_FILENO, argv[0], strlen(argv[0]));
	int fd = open(argv[1], 0);
	file = fd;
	unsigned long size = lseek(fd, 0, SEEK_END);
	lseek(fd, 0, SEEK_SET);
	read(fd, &buffer, size);
	write(STDOUT_FILENO, &buffer, size);
	int c;
	char *args[] = {"Hello World!", NULL};
	posix_spawn(&c, "/bin/echo", NULL, NULL, args, NULL);
	if(fork() == 0)
		write(STDOUT_FILENO, "cunt\n", strlen("cunt\n"));
	posix_spawn(&c, "/bin/echo", NULL, NULL, args, NULL);
	write(STDOUT_FILENO, "STATUS: OK\n", strlen("STATUS: OK\n"));
	return 0;
}
