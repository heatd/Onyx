#!/bin/python3
# Copyright (c) 2021 Pedro Falcato
# This file is part of Onyx, and is released under the terms of the MIT License
# check LICENSE at the root directory for more information
#
# SPDX-License-Identifier: MIT
#
import sys
import clang.cindex
import json

class Syscall:
    
    def __init__(self, name, args, return_type, nr):
        self.name = name
        self.nr = nr
        self.nr_args = len(args)
        self.args = args
        self.return_type = return_type

syscall_list = []
syscalls_tu = None

syscalls_that_dont_exist = ["nosys", "gethostname"]

special_syscalls = {"sigreturn": "__NR_rt_sigreturn", "sigaction": "__NR_rt_sigaction", "sigprocmask": "__NR_rt_sigprocmask",
                    "sigsuspend": "__NR_rt_sigsuspend", "pread": "__NR_pread64", "pwrite": "__NR_pwrite64"}

def find_number(name):
    wanted_define = special_syscalls.get(name, "__NR_" + name)

    for node in syscalls_tu.cursor.get_children():
        if not node.kind.is_preprocessing():
            continue
        
        if not node.spelling.startswith("__NR"):
            continue

        sysname = None
        nr = 0
        for c in node.get_tokens():

            if c.kind == clang.cindex.TokenKind.IDENTIFIER:
                sysname = c.spelling
            
            if c.kind == clang.cindex.TokenKind.LITERAL:
                nr = int(c.spelling)

        if not sysname:
            print("Error: Bad syscall.h")
            exit(1)
        
        if not sysname == wanted_define:
            continue
        
        print(f'{sysname} has syscall number {nr}')

        return nr

    print("Possibly bad syscall " + name)

def parse_syscall(node):
    args = node.get_arguments()

    arg_list = []
    name = node.spelling[len("sys_"):]

    if name in syscalls_that_dont_exist:
        return

    for a in args:
        arg_list.append((a.type.spelling, a.spelling))
    
    syscall_list.append(Syscall(name, arg_list, node.result_type.spelling, find_number(name)))

def find_syscall_defs(node):

    if node.kind == clang.cindex.CursorKind.FUNCTION_DECL:
        function_name = node.displayname

        if function_name.startswith("sys_"):
            parse_syscall(node)
    

    for c in node.get_children():
        find_syscall_defs(c)

index = clang.cindex.Index.create()
syscalls_tu = index.parse("musl/arch/x86_64/bits/syscall.h", options = clang.cindex.TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD)
tu = index.parse(sys.argv[1])

find_syscall_defs(tu.cursor)

syscall_list.sort(key = lambda x: x.nr)

out = json.dumps(syscall_list, indent = 4, default = vars)

with open("syscall_table.json", "w") as file:
    file.write(out)
