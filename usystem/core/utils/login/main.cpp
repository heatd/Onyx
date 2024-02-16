/*
 * Copyright (c) 2017 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <err.h>
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

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>

char *program_name = nullptr;

/* Set the uid and gid */
void switch_users(gid_t gid, uid_t uid)
{
    syscall(SYS_setuid, uid);
    syscall(SYS_setgid, gid);
}

static struct termios old_termios;

int hide_stdin()
{
    struct termios attr;
    tcgetattr(STDIN_FILENO, &attr);
    memcpy(&old_termios, &attr, sizeof(struct termios));
    attr.c_lflag &= ~ECHO; /* Clear ECHO */
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &attr);

    return 0;
}

int reset_terminal()
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

    return strcmp(password_hash.c_str(), resulting_hash) == 0;
}

static void self_exec(const std::string &name)
{
    pid_t pid = fork();

    if (pid < 0)
    {
        perror("fork");
        exit(126);
    }

    if (pid == 0)
    {
        execl("/bin/login", "/bin/login", name.c_str(), nullptr);
        perror("execl");
        exit(126);
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

void show_motd()
{
    try
    {
        std::fstream file{"/etc/motd"};
        if (!file.is_open())
            return;

        std::stringstream ss;
        ss << file.rdbuf();
        std::printf("\n%s\n", ss.str().c_str());
    }
    catch (std::exception &e)
    {
    }
}

bool has_autologin()
{
    return access("/etc/autologin", R_OK) == 0;
}

std::string get_autologin()
{
    std::fstream file{"/etc/autologin"};
    if (!file.is_open())
        throw std::runtime_error("autologin access()'d but failed to be opened");

    std::stringstream ss;
    ss << file.rdbuf();
    auto user = ss.str();
    user.erase(std::remove(user.begin(), user.end(), '\n'), user.cend());
    return user;
}

int main(int argc, char **argv)
{
    if (argc < 2)
        self_exec_for_every_tty();

    const char *tty = argv[1];

    // Become a session leader, so we can get a new controlling terminal
    if (setsid() < 0)
        err(1, "setsid");

    int ttyfd = open(tty, O_RDWR);
    if (ttyfd < 0)
        err(1, "open: %s", tty);

    close(0);
    close(1);
    close(2);

    for (int i = 0; i < 3; i++)
    {
        if (dup(ttyfd) < 0)
        {
            write(ttyfd, "login: dup failed\n", strlen("login: dup failed\n"));
            return 1;
        }
    }

    close(ttyfd);

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

        if (has_autologin())
        {
            username = get_autologin();
            printf("%s (autologin)\n", username.c_str());
        }
        else
        {
            if (get_input(username) < 0)
            {
                perror("get_input");
                return 1;
            }
        }

        printf("password:");
        fflush(stdout);

        hide_stdin();

        user = getpwnam(username.c_str());
        if (!user)
        {
            reset_terminal();
            printf("\nLogin invalid. Try again\n");
            continue;
        }

        if (!user->pw_passwd[0])
            break;

        if (get_input(password) < 0)
        {
            reset_terminal();
            perror("get_input");
            return 1;
        }

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

    show_motd();

    char *args[] = {nullptr, nullptr};
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
