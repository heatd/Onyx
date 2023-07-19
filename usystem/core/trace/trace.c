/*
 * Copyright (c) 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <err.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#include <uapi/ktrace.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

struct tracing_header
{
    u32 evtype;
    // Size of tracing record, including the header
    u16 size;
    unsigned int cpu;
    // Timestamp, in nanoseconds
    u64 ts;
} __attribute__((packed));

enum traced_event_arg_type
{
    ARG_INTEGER = 0,
    ARG_STRING
    // TODO: ARG_ARRAY
};

struct traced_event_arg
{
    const char *name;
    enum traced_event_arg_type type;
    int size;
    int offset;
    int signed_ : 1;
    int ignore : 1;
};

struct traced_event
{
    const char *category;
    const char *name;
    const char *format;
    u32 evid;
    struct traced_event_arg *args;
    size_t nr_args;
    int is_duration : 1;
    struct traced_event *next;
};

#define NS_PER_SEC 1000000000UL
#define NS_PER_MS  1000000UL
#define NS_PER_US  1000UL

void output_json_ev_boilerplate(const char *name, const char *cats, char type, pid_t pid, pid_t tid,
                                u64 ts, FILE *file)
{
    fprintf(file,
            "{\"name\": \"%s\", \"cat\": \"%s\", \"ph\": \"%c\", \"pid\": %d, \"tid\": %d, \"ts\": "
            "%lu}",
            name, cats, type, pid, tid, ts);
}

#define TRACE_ARG_MAX 256

struct trace_arg
{
    char name[TRACE_ARG_MAX];
    char val[TRACE_ARG_MAX];
};

static void output_complete_event(const char *name, const char *cat, pid_t pid, pid_t tid, u64 ts,
                                  u64 dur, struct trace_arg *args, size_t nr_args, FILE *file)
{
    fprintf(file,
            "{\"name\": \"%s\", \"cat\": \"%s\", \"ph\": \"X\", \"pid\": %d, \"tid\": %d, \"ts\": "
            "%lu, \"dur\": %lu",
            name, cat, pid, tid, ts, dur);
    if (nr_args > 0)
    {
        fprintf(file, ", \"args\": {");
        int printcomma = 0;
        while (nr_args-- > 0)
        {
            if (printcomma == 1)
                fputc(',', file);
            fprintf(file, "\"%s\":%s", args->name, args->val);
            args++;
            printcomma = 1;
        }
        fputc('}', file);
    }

    fputc('}', file);
}

static void output_inst_event(const char *name, const char *cat, pid_t pid, pid_t tid, u64 ts,
                              struct trace_arg *args, size_t nr_args, FILE *file)
{
    fprintf(file,
            "{\"name\": \"%s\", \"cat\": \"%s\", \"ph\": \"i\", \"pid\": %d, \"tid\": %d, \"ts\": "
            "%lu",
            name, cat, pid, tid, ts);
    if (nr_args > 0)
    {
        fprintf(file, ", \"args\": {");
        int printcomma = 0;
        while (nr_args-- > 0)
        {
            if (printcomma == 1)
                fputc(',', file);
            fprintf(file, "\"%s\":%s", args->name, args->val);
            args++;
            printcomma = 1;
        }
        fputc('}', file);
    }

    fputc('}', file);
}

struct traced_event *events, *evtail;

struct traced_event *get_ev(u32 evid)
{
    for (struct traced_event *ev = events; ev; ev = ev->next)
        if (ev->evid == evid)
            return ev;
    return NULL;
}

void parse_format_args(struct traced_event *ev)
{
    /* Ok, let's parse the fields in format
     * example format: "field:u32 evtype;\nfield: u16 size;\nfield:u32 cpu;\nfield: u64 ts; cond:
     * TIME\nfield:u64 end_ts; cond: TIME;\nfield:u32 irqn;\n"
     * fields specify individual struct fields (header included), the types are straight forward,
     * some fields may be conditional on certain flags, like TIME in this example. One line
     * describes one field.
     */

    const char *s = ev->format;
    ev->is_duration = 0;
    int offset = 0;
    while (s)
    {
        if (*s == '\0')
            break;
        // skip 6 for "field:"
        s += 6;
        char type[64];
        char varname[64];
        if (sscanf(s, " %s %[^;]s", type, varname) != 2)
        {
            fprintf(stderr, "ruhroh: sscanf failed to parse format\n");
            exit(1);
        }

        printf("%s %s;\n", type, varname);

        struct traced_event_arg *arg =
            reallocarray(ev->args, sizeof(struct traced_event_arg), ev->nr_args + 1);
        if (!arg)
            err(1, "reallocarray");
        ev->args = arg;
        arg += ev->nr_args;
        ev->nr_args++;

        memset(arg, 0, sizeof(*arg));

        arg->name = strdup(varname);
        if (!arg->name)
            err(1, "strdup");

        arg->offset = offset;

        if (!strcmp(type, "char["))
        {
            // it's a string
            arg->type = ARG_STRING;
            arg->size = strtoul(type + 5, NULL, 10);
        }
        else
        {
            // Probably a number, we only support sized u- and s- right now.
            arg->type = ARG_INTEGER;
            if (type[0] == 's')
                arg->signed_ = 1;
            arg->size = strtoul(type + 1, NULL, 10) / 8;
        }

        if (!strcmp(varname, "end_ts"))
        {
            printf("event has duration\n");
            ev->is_duration = 1;
            arg->ignore = 1;
        }

        offset += arg->size;

        s = strchr(s, '\n');

        if (s)
            s++;
    }
}

void output_ev(u8 *raw, struct traced_event *ev, FILE *file)
{
    struct trace_arg *tas = NULL;
    int nr_tas = 0;
    struct tracing_header *header = (void *) raw;
    u64 start = header->ts;
    u64 end = 0;

    for (size_t i = 0; i < ev->nr_args; i++)
    {
        struct traced_event_arg *arg = ev->args + i;
        /* The first 4 args are really uninteresting, just the header we know... */
        if (i < 4)
        {
            raw += arg->size;
            continue;
        }

        if (!strcmp(arg->name, "end_ts"))
        {
            // End timestamp!
            end = *(u64 *) raw;
            raw += 8;
            continue;
        }

        tas = reallocarray(tas, sizeof(struct trace_arg), nr_tas + 1);
        if (!tas)
            err(1, "reallocarray");

        struct trace_arg *t = tas + nr_tas++;
        strcpy(t->name, arg->name);
        if (arg->type == ARG_INTEGER)
        {
            uintmax_t max = 0;
            memcpy(&max, raw, arg->size);
            sprintf(t->val, arg->signed_ ? "%lld" : "%llu", max);
        }
        else if (arg->type == ARG_STRING)
        {
            memcpy(t->val, raw, arg->size);
        }

        raw += arg->size;
    }

    if (ev->is_duration)
    {
        u64 dur = (end - start) / NS_PER_US;
        output_complete_event(ev->name, ev->category, 0, header->cpu, start / NS_PER_US, dur, tas,
                              nr_tas, file);
    }
    else
        output_inst_event(ev->name, ev->category, 0, header->cpu, start / NS_PER_US, tas, nr_tas,
                          file);
}

void output_json(u8 *buf, u8 *bufend, FILE *file)
{
    // Open the JSON array
    fprintf(file, "[");

    while (buf != bufend)
    {
        struct tracing_header *header = (u8 *) buf;

        /*if (header->evtype == TRACING_EVTYPE_HARDIRQ)
        {
            struct tracing_irq_hardirq *hirq = (struct tracing_irq_hardirq *) header;
            u64 start = hirq->header.ts / NS_PER_US;
            u64 end = hirq->end_ts / NS_PER_US;
            u64 dur = end - start;
            struct trace_arg a;
            strcpy(a.name, "irqn");
            sprintf(a.val, "%u", hirq->irq_nr);
            output_complete_event("hardirq", "irq", 0, hirq->header.cpu, start, dur, &a, 1, file);
        }
        else*/
        struct traced_event *ev = get_ev(header->evtype);

        if (!ev)
            fprintf(stderr, "Evtype %x unknown\n", header->evtype);
        else
            output_ev(buf, ev, file);

        buf += header->size;
        if (buf != bufend)
        {
            // Adding a comma for the next line
            fprintf(file, ",\n");
        }
    }

    fprintf(file, "]\n");
}

void add_traced_event(int fd, const char *name)
{
    struct ktrace_getevid_format buf;
    strcpy(buf.name, name);
    buf.evid = 0;

    if (ioctl(fd, KTRACEGETEVID, &buf) < 0)
        err(1, "KTRACEGETEVID");

    struct ktrace_event_format *form = malloc(sizeof(*form) + 4096);
    if (!form)
        err(1, "malloc");
    form->evid = buf.evid;
    form->format_size = 4096;

    if (ioctl(fd, KTRACEGETFORMAT, form) < 0)
        err(1, "KTRACEGETFORMAT");
    printf("format for evid %u: %s\n", form->evid, form->format);

    struct traced_event *ev = calloc(1, sizeof(*ev));
    if (!ev)
        err(1, "malloc");
    ev->evid = form->evid;
    ev->format = form->format;

    // Split the cat.name into two strings
    char *cat = strchr(name, '.') + 1;
    ev->name = strdup(cat);
    ev->category = strndup(name, cat - name - 1);

    if (!ev->name || !ev->category)
        err(1, "strdup");

    parse_format_args(ev);
    ev->next = NULL;

    if (!events)
        events = ev;
    if (evtail)
        evtail->next = ev;
    evtail = ev;

    struct ktrace_enable en;
    en.status = KTRACE_ENABLE_STATUS_ENABLED;
    en.buffer_size = 0x2000000;
    en.flags = TRACE_EVENT_TIME;
    en.evid = ev->evid;
    if (ioctl(fd, KTRACEENABLE, &en) < 0)
        err(1, "KTRACEENABLE");
}

int main(int argc, char **argv, char **envp)
{
    u8 *endbuf;
    u8 *bufp;
    u8 *end;
    int cpufds[256];
    int ncpus = 0;
    int fd = open("/dev/ktrace", O_RDWR | O_CLOEXEC);
    if (fd < 0)
        err(1, "open(/dev/ktrace)");

    // add_traced_event(fd, "irq.hardirq");
    add_traced_event(fd, "wb.dirty_inode");

    endbuf = mmap(NULL, 0x2000000 * 4, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);

    if (endbuf == MAP_FAILED)
        err(1, "mmap");
    bufp = endbuf;
    end = bufp + 0x2000000 * 4;

    int buffd = 0;

    while ((buffd = ioctl(fd, KTRACEGETBUFFD, &ncpus)) >= 0)
    {
        cpufds[ncpus++] = buffd;
    }

    pid_t pid = fork();

    if (pid == 0)
    {
        if (execve(argv[1], argv + 1, envp) < 0)
            err(1, "execve");
    }

    int keep_running = 1;
    while (keep_running)
    {
        usleep(500000);

        if (waitpid(pid, NULL, WNOHANG) > 0)
            keep_running = 0;
        for (int i = 0; i < ncpus; i++)
        {
            ssize_t len = read(cpufds[i], bufp, end - bufp);
            if (len < 0)
                err(1, "read");
            bufp += len;
        }
    }

    printf("Read %zu bytes\n", bufp - endbuf);

    output_json(endbuf, bufp, stdout);

    // TODO: Disable
    return 0;
}
