extern int open(const char*, int flags);
extern int read(int fd, void *buf, unsigned int count);
extern int write(int fd, void *buf, unsigned int count);
extern unsigned long lseek(int fd, unsigned long offset, int whence);
int file = 0;
int main()
{
	const char *str = "/usr/include/dirent.h";
	int fd = open(str, 0);
	file = fd;
	char buffer[500];
	read(fd, &buffer, 500);
	write(1, &buffer, 500);
	unsigned long size = lseek(fd, 0, 3);
	while(1);
	return 0;
}
