#ifndef _LINUX_KOBJECT_H
#define _LINUX_KOBJECT_H

#define kobject_uevent_env(kobj, action, envp) ({(void) envp; true;})

/* todo: move to sysfs.h */
#define sysfs_create_link(...) (0)
#define sysfs_remove_link(...) do { } while (0)

#endif
