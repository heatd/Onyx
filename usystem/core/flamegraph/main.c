/*
 * Copyright (c) 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#define _GNU_SOURCE
#include <err.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <onyx/public/perf_probe.h>

#include <symbolize/symbolize.h>

bool tracing_wait = false;

struct flame_graph_entry_freq
{
    struct flame_graph_entry e;
    size_t freq;
};

struct flame_graph_entry_freqmap
{
    struct flame_graph_entry_freq *freqmap;
    size_t nr_freqs;
    size_t wpos;
};

void stub(int sig)
{
    (void) sig;
}

bool is_same_stack(struct flame_graph_entry *e, struct flame_graph_entry *e2)
{
    const size_t frames = tracing_wait ? FLAME_GRAPH_FRAMES - 1 : FLAME_GRAPH_FRAMES;
    for (size_t i = 0; i < frames; i++)
    {
        if (e->rips[i] != e2->rips[i])
            return false;
        if (e->rips[i] == 0)
            break;
    }

    return true;
}

void add_to_freqmap(struct flame_graph_entry_freqmap *freqmap, struct flame_graph_entry *e)
{
    size_t i;
    for (i = 0; i < freqmap->wpos; i++)
    {
        if (freqmap->freqmap[i].e.rips[0] == e->rips[0])
        {
            if (is_same_stack(&freqmap->freqmap[i].e, e))
            {
                if (tracing_wait)
                {
                    freqmap->freqmap[i].freq += e->rips[31];
                }
                else
                    freqmap->freqmap[i].freq++;
                return;
            }
        }
    }

    struct flame_graph_entry_freq *f = &freqmap->freqmap[freqmap->wpos++];
    memcpy(&f->e, e, sizeof(*e));
    f->freq = tracing_wait ? 1 : e->rips[31];
}

struct symbolize_ctx ctx;

void print_stack(struct flame_graph_entry_freq *f)
{
    const size_t frames = tracing_wait ? FLAME_GRAPH_FRAMES - 1 : FLAME_GRAPH_FRAMES;
    for (size_t i = 0; i < frames; i++)
    {
        if (f->e.rips[i] == 0)
            break;
        char symbuf[1024];
        int st = symbolize_symbolize(&ctx, f->e.rips[i], symbuf, sizeof(symbuf));

        if (st < 0)
        {
            warn("symbolize_symbolize");
            snprintf(symbuf, 1024, "0x%lx", f->e.rips[i]);
        }

        printf("        vmonyx`%s\n", symbuf);
    }
}

void print_fmap(struct flame_graph_entry_freqmap *fmap)
{
    for (size_t i = 0; i < fmap->wpos; i++)
    {
        struct flame_graph_entry_freq *f = &fmap->freqmap[i];
        print_stack(f);
        printf("          %zu\n\n", f->freq);
    }
}

static void print_usage(void)
{
    printf("Usage: flamegraph [-w]\n");
    printf("Collects kernel flamegraphs and prints them to stdout.\n"
           "The format may then be collected by FlameGraph's stackcollapse.pl"
           " and processed to create a .svg\n");
    printf("\n  -w       Collect a wait flamegraph instead of a CPU one\n");
}

int main(int argc, char **argv)
{
    int c;

    while ((c = getopt(argc, argv, "w")) != -1)
    {
        switch (c)
        {
            case 'w':
                tracing_wait = true;
                break;
            case 'h':
            case '?':
                print_usage();
                return c != 'h';
        }
    }

    int kfd = open("/boot/vmonyx", O_RDONLY | O_CLOEXEC);
    if (kfd < 0)
        err(1, "error opening /boot/vmonyx");

    if (symbolize_exec(kfd, &ctx) < 0)
        err(1, "error initializing symbolization");

    signal(SIGALRM, stub);

    int fd = open("/dev/perf-probe", O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        err(1, "error opening perf-probe");

    int enable = 1;
    if (ioctl(fd, tracing_wait ? PERF_PROBE_ENABLE_DISABLE_WAIT : PERF_PROBE_ENABLE_DISABLE_CPU,
              &enable) < 0)
        err(1, "error enabling perf-probe");

    alarm(10);
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGALRM);
    int sig;
    if (sigwait(&set, &sig) < 0)
        err(1, "sigwait");

    enable = 0;
    if (ioctl(fd, tracing_wait ? PERF_PROBE_ENABLE_DISABLE_WAIT : PERF_PROBE_ENABLE_DISABLE_CPU,
              &enable) < 0)
        err(1, "error disabling perf-probe");

    int buflen = ioctl(fd, PERF_PROBE_GET_BUFFER_LENGTH);
    if (buflen < 0)
        err(1, "error getting perf-probe buflen");

    struct flame_graph_entry *buf = malloc(buflen);
    if (!buf)
        err(1, "malloc");

    if (ioctl(fd, PERF_PROBE_READ_DATA, buf) < 0)
        err(1, "error getting perf-probe result");

    size_t nentries = buflen / sizeof(struct flame_graph_entry);

    struct flame_graph_entry_freq *freqs = calloc(sizeof(struct flame_graph_entry_freq), nentries);
    if (!freqs)
        err(1, "error allocating freqmap");
    struct flame_graph_entry_freqmap fmap;
    fmap.freqmap = freqs;
    fmap.nr_freqs = nentries;
    fmap.wpos = 0;

    for (size_t i = 0; i < nentries; i++)
    {
        if (buf[i].rips[0] == 0)
            continue;
        add_to_freqmap(&fmap, &buf[i]);
    }

    print_fmap(&fmap);
}
