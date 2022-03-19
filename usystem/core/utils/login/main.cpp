/*
 * Copyright (c) 2017 - 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <shadow.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <termios.h>
#include <unistd.h>

#include <filesystem>
#include <string>

char *program_name = NULL;

/* Set the uid and gid */
void switch_users(gid_t gid, uid_t uid)
{
    syscall(SYS_setuid, uid);
    syscall(SYS_setgid, gid);
}

static struct termios old_termios;

int hide_stdin(void)
{
    struct termios attr;
    tcgetattr(STDIN_FILENO, &attr);
    memcpy(&old_termios, &attr, sizeof(struct termios));
    attr.c_lflag &= ~ECHO; /* Clear ECHO */
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &attr);

    return 0;
}

int reset_terminal(void)
{
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &old_termios);
    return 0;
}

#define TEMP_BUF_SIZE 1024
int get_input(std::string &str)
{
    char *buf = (char *) malloc(TEMP_BUF_SIZE);
    if (!buf)
        return -1;
    bzero(buf, TEMP_BUF_SIZE);
    bool should_stop = false;
    while (!should_stop && fgets(buf, TEMP_BUF_SIZE, stdin))
    {
        char *pos;
        if ((pos = strchr(buf, '\n')))
        {
            should_stop = true;
            *pos = '\0';
        }

        str += buf;
    }

    explicit_bzero(buf, TEMP_BUF_SIZE);
    free(buf);

    return 0;
}

bool compare_passwords(struct spwd *spwd, std::string &password)
{
    /* Hash format: $algorithm$salt$hash */
    std::string password_hash(spwd->sp_pwdp);

    std::size_t algo_pos = password_hash.find('$');
    auto salt_pos = password_hash.find('$', algo_pos + 1);
    auto hash_pos = password_hash.find('$', salt_pos + 1);
    if (algo_pos == std::string::npos || salt_pos == std::string::npos ||
        hash_pos == std::string::npos)
    {
        printf("Malformed shadow file.\n");
        return false;
    }

    std::string salt;
    salt.assign(password_hash, algo_pos, hash_pos - algo_pos);

    const char *resulting_hash = crypt(password.c_str(), salt.c_str());

    if (!strcmp(password_hash.c_str(), resulting_hash))
        return true;
    return false;
}

static void self_exec(const std::string &name)
{
    pid_t pid = fork();

    if (pid < 0)
    {
        perror("fork");
        abort();
    }

    if (pid == 0)
    {
        execl("/bin/login", "/bin/login", name.c_str(), nullptr);
        perror("execl");
        abort();
    }
}

void self_exec_for_every_tty()
{
    for (const auto &entry : std::filesystem::directory_iterator("/dev"))
    {
        auto name = entry.path().filename().string();
        if (name.starts_with("tty") && name.length() > 3)
        {
            self_exec(std::string("/dev/" + name));
        }
    }

    // HACK: Make sure we don't take any of our possible session members with us by sleeping 10
    // seconds
    sleep(10);
    exit(0);
}

int main(int argc, char **argv, char **envp)
{
    setsid();

    if (argc < 2)
        self_exec_for_every_tty();

    const char *tty = argv[1];

    int flags[] = {O_RDONLY, O_WRONLY, O_WRONLY};

    close(0);
    close(1);
    close(2);

    for (int i = 0; i < 3; i++)
    {
        int fd = open(tty, flags[i]);

        if (fd < 0)
            return 1;
    }

    program_name = argv[0];
    printf("%s: ", argv[0]);
    fflush(stdout);
    struct passwd *user;

    tcsetpgrp(0, getpid());

    while (true)
    {
        std::string username;
        std::string password;

        printf("username:");
        fflush(stdout);

        if (get_input(username) < 0)
        {
            perror("get_input");
            return 1;
        }

        printf("password:");
        fflush(stdout);

        hide_stdin();

        if (get_input(password) < 0)
        {
            reset_terminal();
            perror("get_input");
            return 1;
        }

        user = getpwnam(username.c_str());
        if (!user)
        {
            reset_terminal();
            printf("\nLogin invalid. Try again\n");
            continue;
        }

        if (!user->pw_name[0])
            break;

        if (user->pw_name[0] == '!' || user->pw_name[0] == '*')
        {
            reset_terminal();
            printf("\nLogin invalid. Try again\n");
            continue;
        }

        auto pass_ent = getspnam(username.c_str());
        if (!pass_ent)
        {
            reset_terminal();
            printf("\nLogin invalid. Try again\n");
            continue;
        }

        if (!compare_passwords(pass_ent, password))
        {
            reset_terminal();
            printf("\nLogin invalid. Try again\n");
            continue;
        }

        break;
    }

    switch_users(user->pw_gid, user->pw_uid);
    /* Set $USER */
    setenv("USER", user->pw_name, 1);
    /* Set $LOGNAME */
    setenv("LOGNAME", user->pw_name, 1);
    /* Set $HOME */
    setenv("HOME", user->pw_dir, 1);
    /* Set $SHELL */
    setenv("SHELL", user->pw_shell, 1);

    if (chdir(user->pw_dir) < 0)
    {
        printf("\nFailed to switch home directories to %s.\n", user->pw_dir);
        perror("chdir");
        reset_terminal();
        return 1;
    }

    char *args[] = {NULL, NULL};
    /* The first character of argv[0] needs to be -, in order to be a login shell */
    args[0] = (char *) malloc(strlen(user->pw_shell) + 2);
    if (!args[0])
    {
        perror("login");
        reset_terminal();
        return 1;
    }
    memset(args[0], 0, strlen(user->pw_shell) + 2);
    strcat(args[0], "-");
    strcat(args[0], user->pw_shell);

    reset_terminal();

    printf("\n");

    if (setpgid(0, 0) < 0)
    {
        perror("setpgid");
        return 1;
    }

    if (execv(user->pw_shell, args) < 0)
    {
        perror("exec");
        return 1;
    }

    return 0;
}
