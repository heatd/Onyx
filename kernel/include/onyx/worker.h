/*
 * Copyright (c) 2017 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 */
#ifndef _KERNEL_WORKER_H
#define _KERNEL_WORKER_H

/* Some convenient defines */
#define WORKER_PRIO_VERY_LOW -10
#define WORKER_PRIO_LOW      0
#define WORKER_PRIO_NORMAL   10
#define WORKER_PRIO_HIGH     20

/* A structure describing a work request for the worker threads */
struct work_request
{
    void (*func)(void *);
    void *param;
    int priority;
    struct work_request *next;
};

/* Initializes worker threads */
void worker_init(void);
/* Schedule work; the higher the priority, the sooner it will be executed */
int worker_schedule(struct work_request *work, int priority);

#endif
