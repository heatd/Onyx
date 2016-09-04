extern int open(const char*, int flags);
extern int read(int fd, void *buf, unsigned int count);
extern int write(int fd, void *buf, unsigned int count);
extern unsigned long lseek(int fd, unsigned long offset, int whence);
int file = 0;
char buffer[0x1000];
int main(int argc, char **argv)
{
	write(1, "cat", 3);
	int fd = open(argv[1], 0);
	file = fd;
	unsigned long size = lseek(fd, 0, 3);
	lseek(fd, 0, 1);
	read(fd, &buffer, size);
	write(1, &buffer, size);
	int c;
	posix_spawn(&c, "/bin/echo");
	write(1, "Spawned /bin/echo!", strlen("Spawned /bin/echo!"));
	while(1);
	return 0;
}
