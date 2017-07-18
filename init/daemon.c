/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <libgen.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <stdbool.h>

#include "init.h"

static int dirfd;
struct daemon *daemons = NULL;

struct daemon *add_daemon(void)
{
	struct daemon *d = malloc(sizeof(struct daemon));
	if(!d)
		return NULL;
	memset(d, 0, sizeof(struct daemon));
	if(!daemons)
		daemons = d;
	else
	{
		struct daemon *s = daemons;
		while(s->next) s = s->next;
		s->next = d;
	}
	return d;
}
void destroy_property_struct(struct property *prop)
{
	for(struct subproperty *p = prop->props; p; p = p->next)
	{
		free(p->name);
		free(p->value);
		free(p);
	}
	free(prop->prop_name);
	free(prop);
}
void destroy_target_struct(target_t *target)
{
	for(struct property *prop = target->properties; prop; prop = prop->next)
	{
		destroy_property_struct(prop);
	}
	free(target);
}
struct property *target_add_property(target_t *target)
{
	struct property *prop = malloc(sizeof(struct property));
	if(!prop)
		return NULL;
	memset(prop, 0, sizeof(struct property));
	if(!target->properties)
	{
		target->properties = prop;
	}
	else
	{
		struct property *p = target->properties;
		while(p->next) p = p->next;
		p->next = prop;
	}
	return prop;
}
struct subproperty *target_add_subproperty(target_t *target)
{
	struct subproperty *prop = malloc(sizeof(struct subproperty));
	if(!prop)
		return NULL;
	memset(prop, 0, sizeof(struct subproperty));
	struct property *curr = target->current_property;
	if(!curr->props)
	{
		curr->props = prop;
	}
	else
	{
		struct subproperty *p = curr->props;
		while(p->next) p = p->next;
		p->next = prop;
	}
	return prop;
}
struct subproperty *get_subproperty(struct property *p, const char *name)
{
	for(struct subproperty *prop = p->props; prop; prop = prop->next)
	{
		if(!strcmp(prop->name, name))
			return prop;
	}
	return NULL;
}
int execute_program(const char *path, const char *type)
{
	bool do_daemon_things = false;
	if(!strcmp(type, "daemon"))
	{
		do_daemon_things = true;
	}
	pid_t pid = fork();
	if(pid < 0)
	{
		fprintf(stderr, "%s: %s: %s\n", __func__, "fork", strerror(errno));
		return -1;
	}
	else if(pid == 0)
	{
		if(do_daemon_things)
		{
			int fd = open("/dev/null", O_RDWR);
			if(fd < 0)
			{
				fprintf(stderr, "%s: %s: %s\n", __func__, "/dev/null", strerror(errno));
				exit(1);
			}
			dup2(fd, STDIN_FILENO);
			dup2(fd, STDOUT_FILENO);
			dup2(fd, STDERR_FILENO);
			chdir("/");
		}
		/* Pass path as argv[0] */
		if(execl(path, path, NULL) < 0)
		{
			/* TODO: Syncronize with the parent */
			fprintf(stderr, "%s: %s: %s\n", __func__, "execl", strerror(errno));
			exit(1);
		}
	}
	else if(pid > 0)
	{
		if(do_daemon_things == false)
			return 0;
		/* We're the parent, register the daemon */
		struct daemon *daemon = add_daemon();
		if(!daemon)
		{
			fprintf(stderr, "%s: %s: %s\n", __func__, "add_daemon", strerror(errno));
			return -1;
		}
		daemon->name = strdup((const char*) basename((char*) path));
		daemon->pid = pid;
	}
	return 0;
}
int process_line(char *line, target_t *target)
{
	if(*line == '#')
		return 0;
	char *saveptr;
	while(*line)
	{
		if(*line == ' ' || *line == '\t')
		{
			line++;
		}
		if(*line == '[')
		{
			line++;
			/* If so, this is a property, register it as one */
			struct property *prop = target_add_property(target);
			if(!prop)
			{
				perror("process_line");
				return -1;
			}
			char *name = strtok_r(line, "]", &saveptr);
			prop->prop_name = strdup(name);
			if(!prop->prop_name)
			{
				perror("process_line");
				return -1;
			}
			target->current_property = prop;
			return 0;
		}
		else
		{
			/* This line is surely a subproperty */
			if(!target->current_property)
				return -1;
			char *buf = strtok_r(line, "=", &saveptr);
			char *subproperty = strdup(buf);
			if(!subproperty)
			{
				perror("process_line");
				return -1;
			}
			char *value = strdup(strtok_r(NULL, "=", &saveptr));
			if(!value)
			{
				perror("process_line");
				return -1;
			}
			if(!target->current_property)
			{
				printf("process_line: Syntax error at %s\n", line);
				return -1;
			}
			struct subproperty *subprop = target_add_subproperty(target);
			if(!subprop)
			{
				free(subproperty);
				perror("process_line");
				return -1;
			}
			subprop->name = subproperty;
			subprop->value = value;
			return 0;
		}
	}
	return -1;
}
int process_target(target_t *target)
{
	char *saveptr;
	struct property *dependencies = NULL;
	struct property *service = NULL;
	/* Process each property */
	for(struct property *prop = target->properties; prop; prop = prop->next)
	{
		if(!strcmp(prop->prop_name, PROPERTY_SERVICE))
		{
			service = prop;
		}
		else if(!strcmp(prop->prop_name, PROPERTY_DEPENDENCIES))
		{
			dependencies = prop;
		}
		else
		{
			printf("WARNING: Property %s is an invalid property; Init will ignore this property, "
				"this may be unwanted behavior\n", prop->prop_name);
		}
	}
	if(dependencies)
	{
		struct subproperty *p = dependencies->props;
		/* Process every subproperty */
		for(; p; p = p->next)
		{
			if(!strcmp(p->name, SUBPROP_WANTS))
			{
				char *string = p->value;
				char *dep = NULL;
				dep = strtok_r(string, " ", &saveptr);
				while(dep)
				{
					int fd = openat(dirfd, dep, O_RDONLY);
					if(fd < 0)
					{
						fprintf(stderr, "process_target: Could not open %s: %s\n", dep, strerror(errno));
						return -1;
					}
					if(exec_target(fd) < 0)
						return -1;
					dep = strtok_r(NULL, " ", &saveptr);
				}
			}
		}
	}
	if(service)
	{
		struct subproperty *p = service->props;
		/* Process every subproperty */
		for(; p; p = p->next)
		{
			if(!strcmp(p->name, SUBPROP_BIN))
			{
				const char *type_ = "regular";
				struct subproperty *type = get_subproperty(service, SUBPROP_TYPE);
				if(type)
					type_ = type->value;
				execute_program(p->value, type_);
			}
		}
	}
	return 0;
}
int exec_target(int fd)
{
	FILE *fp = fdopen(fd, "r");
	char *buffer;
	char *pos;
	int status = 0;
	target_t *target;
	if(!fp)
	{
		status = -1;
		goto ret;
	}
	buffer = malloc(1024);
	if(!buffer)
	{
		status = -1;
		goto ret;
	}
	memset(buffer, 0, 1024);
	
	target = malloc(sizeof(target_t));
	if(!target)
	{
		status = -1;
		goto ret;
	}
	target->properties = NULL;
	/* Read the target file */
	while(fgets(buffer, 1024, fp) != NULL)
	{
		if((pos = strchr(buffer, '\n')))
    			*pos = '\0';
		if(strlen(buffer) == 0)
			continue;
		if(process_line(buffer, target) < 0)
		{
			printf("Error processing line %s!\n", buffer);
			status = -1;
			goto ret;
		}
		memset(buffer, strlen(buffer), 0);
	}
	/* Process the target now that we're finished */
	process_target(target);
ret:
	if(fp)
		fclose(fp);
	else
		close(fd);
	if(buffer)	free(buffer);
	if(target) destroy_target_struct(target);
	return status;
}
int find_targets(const char *dir)
{
	int status;
	int fd;
	/* First, open the directory */
	dirfd = open(dir, O_DIRECTORY | O_RDONLY);
	if(dirfd < 0)
	{
		fprintf(stderr, "%s: %s: %s\n", __func__, dir, strerror(errno));
		return -1;
	}
	/* Now, use dirfd with openat in order to open the default.target file */
	fd = openat(dirfd, "default.target", O_RDONLY);
	if(fd < 0)
	{
		perror("find_targets");
		close(dirfd);
		return -1;
	}
	status = exec_target(fd);
	close(dirfd);
	/* We don't close fd here because it might've been closed by fclose, maybe we can handle this better? */
	return status;
}
int exec_daemons(void)
{
	int status = 0;
	if((status = find_targets(DEFAULT_TARGETS_PATH)) < 0)
		return status;
	return 0;
}
