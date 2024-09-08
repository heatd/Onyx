/*
 * Copyright (c) 2023 - 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>

#if defined(__onyx__) || defined(__linux__)
#include <sys/statfs.h>
#elif defined(__FreeBSD__)
#include <sys/param.h>
#endif
#include <unistd.h>

void openslash(void)
{
    // Test for basic POSIX "/" open
    int fd = open("/", O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        err(1, "openslash");
    close(fd);
}

void openslashslash(void)
{
    /* Test if opening // works */
    int fd = open("////", O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        err(1, "openslashslash");
    close(fd);
    if (access("//", X_OK) < 0)
        err(1, "openslashslash");
}

#define ASSERT_ERRNO(_fd, _err)                                                                \
    do                                                                                         \
    {                                                                                          \
        int __nfd = (_fd);                                                                     \
        if (__nfd != -1)                                                                       \
            errx(1, "%s: %s returned valid fd\n", __func__, #_fd);                             \
        if (errno != (_err))                                                                   \
            err(1, "%s: %s expected errno %d (%s)", __func__, #_fd, (_err), strerror((_err))); \
    } while (0);

#define ASSERT_TWO_ERRNO(_fd, _err, _err2)                                             \
    do                                                                                 \
    {                                                                                  \
        int __nfd = (_fd);                                                             \
        if (__nfd != -1)                                                               \
            errx(1, "%s: %s returned valid fd\n", __func__, #_fd);                     \
        if (errno != (_err) && errno != (_err2))                                       \
            err(1, "%s: %s expected errno %d (%s) or %d (%s)", __func__, #_fd, (_err), \
                strerror((_err)), (_err2), strerror((_err2)));                         \
    } while (0);

void openempty(void)
{
    ASSERT_ERRNO(open("", O_RDONLY), ENOENT);
}

void openpathtoolarge(void)
{
    char path[PATH_MAX + 1];
    for (int i = 0; i < PATH_MAX; i++)
    {
        /* Generate a/a/a/a/a/a/a/a/a/... */
        path[i] = i & 1 ? '/' : 'a';
    }

    path[PATH_MAX] = '\0';

    ASSERT_ERRNO(open(path, O_RDONLY), ENAMETOOLONG);

    char name[NAME_MAX + 2];

    // Generate a name too long
    for (int i = 0; i < NAME_MAX + 1; i++)
        name[i] = 'a';
    name[NAME_MAX + 1] = '\0';
    ASSERT_ERRNO(open(name, O_RDONLY), ENAMETOOLONG);
}

static void umount_tmp(void)
{
#if defined(__onyx__) || defined(__linux__)
    if (umount("/tmp") < 0)
    {
        perror("umount(\"/tmp\")");
        _exit(1);
    }
#endif
}

#ifdef __onyx__
#define TMPFS_MAGIC 0x11102002
#else
#define TMPFS_MAGIC 0x01021994
#endif

static void openmountpoint(void)
{
#if defined(__onyx__) || defined(__linux__)
    struct statfs buf;
    int fd = open("/tmp", O_RDONLY);
    if (fd < 0)
        err(1, __func__);

    if (fstatfs(fd, &buf) < 0)
    {
        err(1, "%s: statfs failed", __func__);
    }

    close(fd);

    if (buf.f_type != TMPFS_MAGIC)
    {
        err(1, "%s: failed mountpoint traversal - bad magic %lx\n", __func__, buf.f_type);
    }
#endif
}

#define SYMLINK       "/tmp/sym"
#define DIR_SYMLINK   "/tmp/dirsym"
#define BROKEN_SYMLNK "/tmp/brokensym"
#define DIR           "/tmp/dir"

static void kill_files(void)
{
    unlink(SYMLINK);
    unlink(BROKEN_SYMLNK);
    unlink(DIR_SYMLINK);
    unlink("/tmp/file1");
    rmdir(DIR);
}

static void setup_tmp(void)
{
    /* XXX FreeBSD mount API does not work exactly like linux, and I can't bother figuring it out
     * Not like it matters much anyway, tmpfs should be mounted on every system...
     */
#if defined(__onyx__) || defined(__linux__)
    /* First, mount tmpfs at /tmp */
    if (mount("none", "/tmp", "tmpfs", 0, NULL) == 0)
    {
        atexit(umount_tmp);
    }
    else
    {
        warn("Failed to mount tmpfs on /tmp");
        warnx("Proceding with tests - tmpfs may not be mounted on /tmp");
    }
#endif

    /* Make sure mountpoint traversal works well */
    openmountpoint();

    atexit(kill_files);

    /* Remove all files that may exist as traces of a past run */
    kill_files();

    /* Make sure broken_non_existent doesn't actually exist (from a prior run or something...)*/
    unlink("/tmp/broken_non_existent");

    if (symlink("broken_non_existent", BROKEN_SYMLNK) < 0)
    {
        err(1, "symlink");
    }

    int fd = open("/tmp/file1", O_CREAT | O_EXCL | O_RDWR, 0644);
    if (fd < 0)
    {
        err(1, "creation of /tmp/file1");
    }

    close(fd);

    if (symlink("file1", SYMLINK) < 0)
    {
        err(1, "symlink");
    }

    if (mkdir(DIR, 0644) < 0)
    {
        err(1, "mkdir");
    }

    if (symlink("dir", DIR_SYMLINK) < 0)
    {
        err(1, "symlink to dir");
    }
}

static void symtraverse(void)
{
    ASSERT_ERRNO(open(BROKEN_SYMLNK, O_RDONLY), ENOENT);
    int fd = open(SYMLINK, O_RDONLY);

    if (fd < 0)
        err(1, "symlink open");
    close(fd);

    /* Test O_NOFOLLOW on open */
#ifdef __FreeBSD__
    /* FreeBSD returns EMLINK vs ELOOP here, for some reason... */
#define NOFOLLOW_ERR EMLINK
#elif defined(__NetBSD__)
#define NOFOLLOW_ERR EFTYPE
#else
#define NOFOLLOW_ERR ELOOP
#endif

    ASSERT_ERRNO(open(SYMLINK, O_RDONLY | O_NOFOLLOW), NOFOLLOW_ERR);
    /* ...and on O_CREAT */
    ASSERT_ERRNO(open(BROKEN_SYMLNK, O_RDONLY | O_NOFOLLOW | O_CREAT, 0644), NOFOLLOW_ERR);

    fd = open(DIR_SYMLINK, O_RDONLY | O_DIRECTORY);
    if (fd < 0)
        err(1, "symlink O_DIRECTORY open");
    close(fd);

    fd = open(DIR_SYMLINK "/", O_RDONLY);
    if (fd < 0)
        err(1, "symlink dir open with trailing slash");
    close(fd);

    if (symlink("/tmp/dir", "/tmp/abs_symlink") < 0)
    {
        err(1, "symlink to dir");
    }

    fd = open("/tmp/abs_symlink", O_RDONLY | O_DIRECTORY);
    int olderr = errno;
    unlink("/tmp/abs_symlink");
    errno = olderr;

    if (fd < 0)
    {
        err(1, "abs symlink doesnt work");
    }

    close(fd);

    /* Check if symlink trailing / requires a directory */

    if (symlink("/tmp/file1/", "/tmp/abs_symlink") < 0)
    {
        err(1, "symlink to file");
    }

    ASSERT_ERRNO(open("/tmp/abs_symlink", O_RDONLY), ENOTDIR);

    unlink("/tmp/abs_symlink");

    /* If a symbolic link is encountered during pathname resolution, the behavior shall depend on
       whether the pathname component is at the end of the pathname and on the function being
       performed. If all of the following are true, then pathname resolution is complete:

       1. This is the last pathname component of the pathname.

       2. The pathname has no trailing slash.

       3. The function is required to act on the symbolic link itself, or certain arguments direct
       that the function act on the symbolic link itself.

       In all other cases, the system shall prefix the remaining pathname, if any, with the contents
       of the symbolic link. If the combined length exceeds {PATH_MAX}, and the implementation
       considers this to be an error, errno shall be set to [ENAMETOOLONG] and an error indication
       shall be returned. Otherwise, the resolved pathname shall be the resolution of the pathname
       just created. If the resulting pathname does not begin with a slash, the predecessor of the
       first filename of the pathname is taken to be the directory containing the symbolic link.
    */

    /* Test 2) and 3) using lstat */

    struct stat buf;
    if (lstat(DIR_SYMLINK, &buf) < 0)
        err(1, "lstat");
    if (!S_ISLNK(buf.st_mode))
        err(1, "lstat opened symlink target");
    /* Attempt to open the actual target by appending / */
    if (lstat(DIR_SYMLINK "/", &buf) < 0)
        err(1, "lstat");
    if (!S_ISDIR(buf.st_mode))
        err(1, "lstat did not open symlink target");
    /* Check that stat properly derefs the symlink */
    if (stat(DIR_SYMLINK, &buf) < 0)
        err(1, "stat");
    if (!S_ISDIR(buf.st_mode))
        err(1, "stat did not open symlink target");

    /* If O_EXCL and O_CREAT are set, and path names a symbolic link, open() shall fail and set
     * errno to [EEXIST], regardless of the contents of the symbolic link. */
    ASSERT_ERRNO(open(BROKEN_SYMLNK, O_RDONLY | O_EXCL | O_CREAT, 0644), EEXIST);
}

static void mbdirtest(void)
{
    /* must-be-dir testing */
    ASSERT_ERRNO(open("/tmp/file1/blah", O_RDONLY), ENOTDIR);
    ASSERT_ERRNO(open("/tmp/file1/", O_RDONLY), ENOTDIR);
    ASSERT_ERRNO(open("/tmp/file1", O_RDONLY | O_DIRECTORY), ENOTDIR);
}

static void createst(void)
{
    ASSERT_ERRNO(open("/tmp/file1", O_CREAT | O_EXCL | O_RDONLY), EEXIST);
    int fd = open("/tmp/file1", O_CREAT | O_RDONLY, 0644);
    if (fd < 0)
        err(1, "createst: O_CREAT on existing file failed");
    close(fd);

    /* Check if open(O_CREAT) creates if the last element is a broken symlink */
    fd = open(BROKEN_SYMLNK, O_CREAT | O_RDONLY, 0644);
    if (fd < 0)
        err(1, "creat on broken symlink");
    close(fd);
    if (unlink("/tmp/broken_non_existent") < 0)
        err(1, "unlink on created broken symlink target");

    /* On [O_CREAT]: The third argument does not affect whether the file is open for reading,
     * writing.*/

    /* XXX this test is partially faulty when running as root :/ */
    fd = open(BROKEN_SYMLNK, O_CREAT | O_RDWR, 0444);
    if (fd < 0)
        err(1, "test if file perms affected O_CREAT'd file failed, they /probably/ are...");
    close(fd);
    if (unlink("/tmp/broken_non_existent") < 0)
        err(1, "unlink on created broken symlink target");

        /* Linux does not currently comply to this */
#ifndef __linux__
    /* [ENOENT] or [ENOTDIR]
       O_CREAT is set, and the path argument contains at least one non- <slash> character and ends
       with one or more trailing <slash> characters. If path without the trailing <slash> characters
       would name an existing file, an [ENOENT] error shall not occur.
     */
    ASSERT_TWO_ERRNO(open(BROKEN_SYMLNK "/", O_CREAT | O_RDONLY), ENOENT, ENOTDIR);
    ASSERT_ERRNO(open(SYMLINK "/", O_CREAT | O_RDONLY), ENOTDIR);
#endif
}

static void looptest(void)
{
    /* If the system detects a loop in the pathname resolution process, it shall set errno to
       [ELOOP] and return an error indication. The same may happen if during the resolution process
       more symbolic links were followed than the implementation allows. This implementation-defined
       limit shall not be smaller than {SYMLOOP_MAX}.
    */

    /* Note: We don't bother testing SYMLOOP_MAX as in practice most systems do not
     * do loop detection but rather keep incrementing nloops until they hit SYMLOOP_MAX, and then
     * stop.
     */
#define LOOPLNK SYMLINK "_loop"
    unlink(LOOPLNK);
    if (symlink(LOOPLNK, LOOPLNK) < 0)
    {
        err(1, "failed to create loop");
    }

    ASSERT_ERRNO(open(LOOPLNK, O_RDONLY), ELOOP);
    unlink(LOOPLNK);
#undef LOOPLNK
}

static void mkdirnameitest(void)
{
    /* If path names a symbolic link, mkdir() shall fail and set errno to [EEXIST]. */
    ASSERT_ERRNO(mkdir(BROKEN_SYMLNK, 0644), EEXIST);
}

static void rmdirnameitest(void)
{
    /* If path names a symbolic link, then rmdir() shall fail and set errno to [ENOTDIR]. */
    ASSERT_ERRNO(rmdir(DIR_SYMLINK), ENOTDIR);
}

static void checknosymderef(void)
{
    /* Check if functions that are specified not to deref, do not deref
     * We only check ones that were not checked yet (lstat, stat were used before, in other tests)
     */
    if (unlink(SYMLINK) < 0)
        err(1, "unlink");
    if (access("/tmp/file1", R_OK) < 0)
        err(1, "unlink is dereferencing target");

    if (symlink("file1", SYMLINK) < 0)
    {
        err(1, "symlink");
    }

    /* rename never follows last-component symlinks either */
    if (rename(SYMLINK, SYMLINK "_2") < 0)
        err(1, "rename");
    if (access("/tmp/file1", R_OK) < 0)
        err(1, "rename is dereferencing oldpath");

    if (rename(SYMLINK "_2", SYMLINK) < 0)
        err(1, "rename");

    if (rename(BROKEN_SYMLNK, SYMLINK) < 0)
        err(1, "rename");

    if (access("/tmp/file1", R_OK) < 0)
        err(1, "rename is dereferencing newpath");

    /* Restore old symlinks */
    if (rename(SYMLINK, BROKEN_SYMLNK) < 0)
        err(1, "rename");

    if (symlink("file1", SYMLINK) < 0)
    {
        err(1, "symlink");
    }

    if (geteuid() == 0)
    {
        /* lchown never derefs, chown should */
        if (lchown(BROKEN_SYMLNK, 1001, -1) < 0)
            err(1, "lchown is dereferencing");

        if (chown(BROKEN_SYMLNK, 1000, -1) == 0)
            err(1, "chown is not dereferencing");
    }
    else
    {
        warnx("not root, skipping chown symlink deref tests...");
    }
}

static void checkperms(void)
{
    if (geteuid() == 0)
    {
        /* Drop euid to unpriv, and then back */
        seteuid(1000);
    }

    /* Make sure we EPERM if we try to search on DIR (which is non-execute read-only) */
    ASSERT_ERRNO(open(DIR "/file", O_RDONLY), EACCES);
    /* Make sure we EPERM if we try to create on NEWDIR (which is execute read) */
#define NEWDIR "/tmp/newdir"
    rmdir(NEWDIR);
    if (mkdir(NEWDIR, 0555) < 0)
        err(1, "mkdir");

    /* make sure it doesn't exist... */
    unlink(NEWDIR "/file");
    ASSERT_ERRNO(open(NEWDIR "/file", O_RDONLY | O_CREAT | O_EXCL, 0644), EACCES);
    rmdir(NEWDIR);
#undef NEWDIR
    /* If we dropped privs, get them back */
    seteuid(0);
}

static void opennondir(void)
{
    ASSERT_ERRNO(open("/tmp/file1/gazump", O_RDONLY), ENOTDIR);
    int fd = open("/tmp/file1", O_RDONLY);

    if (fd < 0)
        err(1, "opennondir: open");
    ASSERT_ERRNO(openat(fd, "gazump", O_RDONLY), ENOTDIR);
    close(fd);
}

static void checkat(void)
{
    /* Fun detail of *at() syscalls: you're not supposed to look at the dirfd if the path is not
     * relative...
     * We only test openat for brevity's sake
     */
    ASSERT_ERRNO(openat(-1, "gazump", O_RDONLY), EBADF);
    int fd = openat(-1, DIR, O_RDONLY);

    if (fd < 0)
        err(1, "checkat");
    close(fd);
}

static void openeisdir(void)
{
    /* [EISDIR] The named file is a directory and oflag includes O_WRONLY or O_RDWR, or includes
     * O_CREAT without O_DIRECTORY
     */
    ASSERT_ERRNO(open(DIR, O_RDWR), EISDIR);
    ASSERT_ERRNO(open(DIR, O_WRONLY), EISDIR);
#ifndef __NetBSD__
    /* NetBSD does not comply to this */
    ASSERT_ERRNO(open(DIR, O_RDONLY | O_CREAT, 0644), EISDIR);
#endif
}

#if defined(__NetBSD__) || defined(__onyx__)
#define OCREATODIR_NETBSD 1
#elif defined(__linux__)
#define OCREATODIR_LINUX 1
#elif defined(__FreeBSD__)
#define OCREATODIR_FREEBSD 1
#endif

static void openocreatdir(void)
{
#define NEWF DIR "_ocreatdir"
    /* O_CREAT | O_DIRECTORY is a weeeeeeiiiiiird case. NetBSD auto-rejects O_CREAT | O_DIRECTORY
     * with EINVAL, FreeBSD opens the directory if dir but else does not create anything (ENOENT),
     * Linux returns -EISDIR if dir, else creates a file and *RETURNS AN ERROR (ENOTDIR)*. *Sigh*.
     * Lets assume Onyx wants to do the NetBSD behavior here (TODO(think about this)).
     */
#if OCREATODIR_NETBSD
    ASSERT_ERRNO(open(DIR, O_CREAT | O_DIRECTORY | O_RDONLY, 0644), EINVAL);
#elif OCREATODIR_FREEBSD
    int fd = open(DIR, O_CREAT | O_DIRECTORY | O_RDONLY);
    if (fd < 0)
        err(1, "fbsd behavior O_CREAT | O_DIRECTORY open with existing dir failed");
    ASSERT_ERRNO(open(NEWF, O_CREAT | O_DIRECTORY | O_RDONLY, 0644), ENOENT);
#elif OCREATODIR_LINUX
    ASSERT_ERRNO(open(DIR, O_CREAT | O_DIRECTORY | O_RDONLY, 0644), EISDIR);
    unlink(NEWF);
    ASSERT_ERRNO(open(NEWF, O_CREAT | O_DIRECTORY | O_RDONLY, 0644), ENOTDIR);
    struct stat buf;
    if (stat(NEWF, &buf) < 0)
        err(1, "stat");
    unlink(NEWF);

    if (!S_ISREG(buf.st_mode))
        err(1, "linux O_CREAT | O_DIRECTORY on non-existent dir did not create a regular file");
#endif
#undef NEWF
}

static void opentrailingslash(void)
{
    ASSERT_ERRNO(open(SYMLINK "/", O_RDONLY), ENOTDIR);
}

static void emptysym(void)
{
#define NEWF SYMLINK "_empty"
    unlink(NEWF);

    if (symlink("", NEWF) < 0)
    {
        /* Linux is expected to fall here */
        warn("symlink");
        warnx("symlink rejects \"\" as a target, cannot test null symlink traversal, skipping...");
        return;
    }

    /* There are two ways to handle empty symlinks.
     * The Solaris way is to interpret them as meaning "current directory"
     * The BSD way is to ENOENT on empty symlinks
     *
     * The BSD way sounds saner here
     */
#if defined(__FreeBSD__) || defined(__onyx__)
    ASSERT_ERRNO(open(NEWF, O_RDONLY), ENOENT);
#endif
    unlink(NEWF);
#undef NEWF
}

static void negativedent(void)
{
    /* Test if negative dentries get in the way. */
    int fd = open("/tmp/filefile", O_RDONLY | O_CREAT | O_EXCL, 0666);
    if (fd < 0)
        err(1, "creation of /tmp/filefile");
    if (unlink("/tmp/filefile") < 0)
        err(1, "unlink failed");
    ASSERT_ERRNO(unlink("/tmp/filefile"), ENOENT);
    ASSERT_ERRNO(open("/tmp/filefile", O_RDONLY), ENOENT);
    if (open("/tmp/filefile", O_RDONLY | O_CREAT | O_EXCL, 0666) < 0)
        err(1, "filefile creation 2 failed");
    unlink("/tmp/filefile");
}

int main(void)
{
    openslash();
    openslashslash();
    openempty();
    openpathtoolarge();
    setup_tmp();
    negativedent();
    opennondir();
    symtraverse();
    mbdirtest();
    createst();
    looptest();
    mkdirnameitest();
    rmdirnameitest();
    checknosymderef();
    checkperms();
    checkat();
    openeisdir();
    openocreatdir();
    opentrailingslash();
    emptysym();

    /* TODO: check for proper deref in rename() for trailing slash cases
     * Linux does not do this.
     */
}
