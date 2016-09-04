#include <unistd.h>
#include <string.h>
int main(int argc, char **argv)
{
	write(STDOUT_FILENO, argv[0], strlen(argv[0]));
	return 0;
}
