#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>

int main(int argc, char **argv)
{
	if(argc < 2)
		return 2;
	
	if(unlinkat(AT_FDCWD, argv[1], AT_REMOVEDIR) < 0)
	{
		perror("unlinkat");
		return 1;
	}

	return 0;
}