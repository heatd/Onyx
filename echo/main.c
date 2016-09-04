extern int open(const char*, int flags);
extern int read(int fd, void *buf, unsigned int count);
extern int write(int fd, void *buf, unsigned int count);
extern unsigned long lseek(int fd, unsigned long offset, int whence);
int main(int argc, char **argv)
{
	write(1, "echo\n", 5);
	while(1);
	return 0;
}
