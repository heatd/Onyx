#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>

int main(int argc, char **argv)
{
	if(argc < 3)
		return 2;
	if(link(argv[1], argv[2]) < 0)
	{
		perror("link");
		return 1;
	}

	return 0;
}