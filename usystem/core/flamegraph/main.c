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

#include <uapi/perf_probe.h>

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

struct symbol
{
    unsigned long value;
    unsigned long size;
    const char *name;
    const char *module;
};

static struct symbol *symbols;
unsigned int nr_symbols;

static int symbol_compare(const void *p1, const void *p2)
{
    const struct symbol *s1 = p1;
    const struct symbol *s2 = p2;
    if (s1->value < s2->value)
        return -1;
    else if (s1->value > s2->value)
        return 1;
    return 0;
}

static void read_symbols(int fd)
{
    FILE *filp = fdopen(fd, "r");
    char *line = NULL, *endptr;
    unsigned int buf_capacity = 0;
    unsigned long value, size;
    const char *name, *module;
    char *tmp;
    size_t n;
    if (!filp)
        return;

    while (getline(&line, &n, filp) != -1)
    {
        if (nr_symbols + 1 > buf_capacity)
        {
            buf_capacity = !buf_capacity ? 2048 : buf_capacity << 1;
            symbols = reallocarray(symbols, buf_capacity, sizeof(struct symbol));
            if (!symbols)
            {
                warnx("Allocation of symbol space failed");
                return;
            }
        }

        /* format: <addr in hex> <size in hex> <one type char> <name> <optional module name> */
        value = strtoul(line, &endptr, 16);
        endptr++;
        size = strtoul(endptr, &endptr, 16);
        endptr++;
        if (*endptr != 't' && *endptr != 'T')
        {
            /* We're only interested in functions */
            continue;
        }

        endptr += 2;
        name = endptr;
        while (*endptr != '\n' && *endptr != ' ')
            endptr++;
        tmp = malloc(endptr - name + 1);
        if (!tmp)
        {
            warnx("Allocation of symbol space failed");
            return;
        }
        memcpy(tmp, name, endptr - name);
        tmp[endptr - name] = 0;
        name = tmp;

        module = NULL;
        if (*endptr == ' ')
        {
            /* Ok, we have a module, get it */
            *(strchr(endptr, '\n')) = 0;
            module = strdup(endptr);
            if (!module)
            {
                warnx("Allocation of symbol space failed");
                return;
            }
        }

        symbols[nr_symbols].name = name;
        symbols[nr_symbols].value = value;
        symbols[nr_symbols].size = size;
        symbols[nr_symbols].module = module;
        nr_symbols++;
    }

    fclose(filp);
    free(line);
    qsort(symbols, nr_symbols, sizeof(struct symbol), symbol_compare);
}

static void init_symbols(void)
{
    int fd = open("/proc/kallsyms2", O_RDONLY | O_CLOEXEC);
    if (fd < 0)
    {
        warn("/proc/kallsyms2 not available");
        fprintf(stderr, "Disabling symbols...\n");
        return;
    }

    read_symbols(fd);
    close(fd);
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
    f->freq = tracing_wait ? e->rips[31] : 1;
}

static int symbolize(unsigned long addr, char *buf, size_t len)
{
    struct symbol *sym;
    long L = 0;
    long R = nr_symbols - 1;
    long m;
    while (L <= R)
    {
        m = (L + R) / 2;
        sym = &symbols[m];
        if (sym->value <= addr && sym->value + sym->size > addr)
        {
            strlcpy(buf, sym->name, len);
            return 0;
        }

        if (sym->value < addr)
            L = m + 1;
        else
            R = m - 1;
    }

    return -1;
}

void print_stack(struct flame_graph_entry_freq *f)
{
    const size_t frames = tracing_wait ? FLAME_GRAPH_FRAMES - 1 : FLAME_GRAPH_FRAMES;
    for (size_t i = 0; i < frames; i++)
    {
        if (f->e.rips[i] == 0)
            break;
        char symbuf[1024];
        int st = symbolize(f->e.rips[i], symbuf, sizeof(symbuf));

        if (st < 0)
        {
            warn("symbolize");
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

    init_symbols();

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
