#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <stdbool.h>
#include <fcntl.h>
#include <unistd.h>

#include <display.h>
#include <window.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

int socket_fd = -1;

#define SERVER_SOCKET_PATH	"/dev/wserver-socket"

int setup_window_server(void)
{
	socket_fd = socket(AF_UNIX, SOCK_DGRAM, 0);

	if(socket_fd < 0)
	{
		perror("socket");
		return -1;
	}

	struct sockaddr_un addr;
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, SERVER_SOCKET_PATH, sizeof(addr.sun_path));
	
	if(bind(socket_fd, (struct sockaddr *) &addr, sizeof(struct sockaddr_un)) < 0)
	{
		perror("bind");
		return -1;
	}

	return 0;
}
