/*
 * Copyright (c) 2017 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */

const char *__errno_table[] = {"Unknown",         "EPERM",
                               "ENOENT",          "ESRCH",
                               "EINTR",           "EIO",
                               "ENXIO",           "E2BIG",
                               "ENOEXEC",         "EBADF",
                               "ECHILD",          "EAGAIN",
                               "ENOMEM",          "EACCES",
                               "EFAULT",          "ENOTBLK",
                               "EBUSY",           "EEXIST",
                               "EXDEV",           "ENODEV",
                               "ENOTDIR",         "EISDIR",
                               "EINVAL",          "ENFILE",
                               "EMFILE",          "ENOTTY",
                               "ETXTBSY",         "EFBIG",
                               "ENOSPC",          "ESPIPE",
                               "EROFS",           "EMLINK",
                               "EPIPE",           "EDOM",
                               "ERANGE",          "EDEADLK",
                               "ENAMETOOLONG",    "ENOLCK",
                               "ENOSYS",          "ENOTEMPTY",
                               "EWOULDBLOCK",     "ENOMSG",
                               "EIDRM",           "ECHRNG",
                               "EL2NSYNC",        "EL3HLT",
                               "EL3RST",          "ELNRNG",
                               "EUNATCH",         "ENOCSI",
                               "EL2HLT",          "EBADE",
                               "EBADR",           "EXFULL",
                               "ENOANO",          "EBADRQC",
                               "EBADSLT",         "EDEADLOCK",
                               "EBFONT",          "ENOSTR",
                               "ENODATA",         "ETIME",
                               "ENOSR",           "ENONET",
                               "ENOPKG",          "EREMOTE",
                               "ENOLINK",         "EADV",
                               "ESRMNT",          "ECOMM",
                               "EPROTO",          "EMULTIHOP",
                               "EDOTDOT",         "EBADMSG",
                               "EOVERFLOW",       "ENOTUNIQ",
                               "EBADFD",          "EREMCHG",
                               "ELIBACC",         "ELIBBAD",
                               "ELIBSCN",         "ELIBMAX",
                               "ELIBEXEC",        "EILSEQ",
                               "ERESTART",        "ESTRPIPE",
                               "EUSERS",          "ENOTSOCK",
                               "EDESTADDRREQ",    "EMSGSIZE",
                               "EPROTOTYPE",      "ENOPROTOOPT",
                               "EPROTONOSUPPORT", "ESOCKTNOSUPPORT",
                               "EOPNOTSUPP",      "ENOTSUP",
                               "ENOTSUP",         "EPFNOSUPPORT",
                               "EAFNOSUPPORT",    "EADDRINUSE",
                               "EADDRNOTAVAIL",   "ENETDOWN",
                               "ENETUNREACH",     "ENETRESET",
                               "ECONNABORTED",    "ECONNRESET",
                               "ENOBUFS",         "EISCONN",
                               "ENOTCONN",        "ESHUTDOWN",
                               "ETOOMANYREFS",    "ETIMEDOUT",
                               "ECONNREFUSED",    "EHOSTDOWN",
                               "EHOSTUNREACH",    "EALREADY",
                               "EINPROGRESS",     "ESTALE",
                               "EUCLEAN",         "ENOTNAM",
                               "ENAVAIL",         "EISNAM",
                               "EREMOTEIO",       "EDQUOT",
                               "ENOMEDIUM",       "EMEDIUMTYPE",
                               "ECANCELED",       "ENOKEY",
                               "EKEYEXPIRED",     "EKEYREVOKED",
                               "EKEYREJECTED",    "EOWNERDEAD",
                               "ENOTRECOVERABLE", "ERFKILL",
                               "EHWPOISON"};

#define NUM_ERRNOS (sizeof(__errno_table) / sizeof(__errno_table[0]))
