#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

int main(int argc, char **argv)
{
	if(argc < 3)
		return 2;
	mode_t mode;
	if(sscanf(argv[2], "%o", &mode) != 1)
	{
		perror("scanf");
		return 1;
	}

	if(mkdir(argv[1], mode) < 0)
	{
		perror("mkdir");
		return 1;
	}

	return 0;
}