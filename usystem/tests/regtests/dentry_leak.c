// SPDX-License-Identifier: GPL-2.0-only
#include <err.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

int main()
{
    if (mkdir("dir", 777) < 0)
        err(1, "mkdir");

#define NFILES 2
    char *files[NFILES] = {"dir/file", "dir/file2"};

    for (int i = 0; i < NFILES; i++)
    {
        int fd = open(files[i], O_CREAT | O_EXCL, 0666);
        if (fd < 0)
            err(1, files[i]);
        close(fd);
    }

    for (int i = 0; i < NFILES; i++)
    {
        if (unlink(files[i]) < 0)
            err(1, "unlink %s", files[i]);
    }

    if (rmdir("dir") < 0)
        err(1, "rmdir");
}
