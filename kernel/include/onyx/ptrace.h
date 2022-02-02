/*
 * Copyright (c) 2017 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */

#include <stdint.h>
#include <sys/user.h>

typedef long ptrace_word_t;

/* All of the following functions are architecture specific */
int ptrace_peek(struct process *process, void *addr, ptrace_word_t *word);
int ptrace_poke(struct process *process, void *addr, ptrace_word_t word);
int ptrace_getregs(struct process *process, struct user_regs_struct *regs);
int ptrace_getfpregs(struct process *process, struct user_fpregs_struct *regs);
