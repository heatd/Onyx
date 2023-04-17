#!/bin/python3
# Copyright (c) 2021 Pedro Falcato
# This file is part of Onyx, and is released under the terms of the MIT License
# check LICENSE at the root directory for more information
#
# SPDX-License-Identifier: MIT
#
import json
import sys

class Syscall:
    
    def __init__(self, name, args, return_type, nr):
        self.name = name
        self.nr = nr
        self.nr_args = len(args)
        self.args = args
        self.return_type = return_type
    
class SyscallDecoder(json.JSONDecoder):
    def __init__(self, *args, **kwargs):
        json.JSONDecoder.__init__(self, object_hook = self.object_hook, *args, **kwargs)
    def object_hook(self, dict):
        if "nr_args" in dict:
            return Syscall(dict["name"], dict["args"], dict["return_type"], dict["nr"])
        return dict

# Outputs a thunk considering the information we already have in the syscall table
def output_syscall_thunk(syscall, output_file):
    syscall_declare = f'{syscall.return_type} sys_{syscall.name}('

    argnum = 0
    for arg in syscall.args:
        syscall_declare += f'{arg[0]} {arg[1]}'
        argnum += 1
        if argnum != syscall.nr_args:
            syscall_declare += ", "

    
    syscall_declare += ");"

    output_file.write(f'{syscall_declare}\n\n')
    thunk_name = f'__sys_{syscall.name}_thunk'

    thunk_function = f'''unsigned long {thunk_name}(unsigned long arg0, unsigned long arg1, unsigned long arg2, 
 unsigned long arg3, unsigned long arg4, unsigned long arg5, unsigned long arg6)\n{{\n    '''
    # Note: If the return type is void, we can't have a return statement

    if syscall.return_type != "void":
        thunk_function += f"return (unsigned long) "
    
    thunk_function += f'sys_{syscall.name}('
    argnum = 0
    for arg in syscall.args:
        # Note that we need to properly cast from unsigned long -> argument type
        # Because arguments are always either numbers <= sizeof(unsigned long) or pointers, this works
        thunk_function += f'({arg[0]}) arg{argnum}'
        argnum += 1

        if argnum != syscall.nr_args:
            thunk_function += ", "
    
    thunk_function += ");\n"
    
    # Dummy return since all thunks return an unsigned long
    if syscall.return_type == "void":
        thunk_function += "return 0;"

    thunk_function += "}\n\n"

    output_file.write(thunk_function)

def output_thunk_file_prologue(syscall_thunk):
    headers = ["unistd.h", "dirent.h", "uapi/signal.h", "stdint.h", "stddef.h", "stdio.h", "uapi/errno.h", "uapi/fcntl.h", "uapi/poll.h",
               "uapi/time.h", "onyx/types.h", "uapi/mman.h", "uapi/resource.h", "uapi/posix-types.h", "sys/utsname.h", "uapi/socket.h", "sys/times.h",
               "sys/sysinfo.h", "platform/syscall.h", "uapi/select.h"]
    
    for header in headers:
        syscall_thunk.write(f'#include <{header}>\n')
    
    syscall_thunk.write("\n")

def output_syscall_table(output_file, syscall_nr_to_thunk_table, max_syscall):
    output_file.write('''typedef unsigned long (*syscall_callback_t)(unsigned long a0, unsigned long a1,
				   unsigned long a2, unsigned long a3,
				   unsigned long a4, unsigned long a5, unsigned long a6);\n''')

    # TODO: Assuming syscall_table_64 is weird if we ever port Onyx to 32-bit
    output_file.write("syscall_callback_t syscall_table_64[] = \n{\n")

    for nr in range(0, max_syscall + 1):
        thunk_name = syscall_nr_to_thunk_table.get(nr, "__sys_nosys_thunk")
        output_file.write(f'    [{nr}] = {thunk_name},\n')
    
    output_file.write("};\n")

def main():
    syscall_list = []

    with open(sys.argv[1], "r") as syscall_table:
        syscall_list = json.loads(syscall_table.read(), cls = SyscallDecoder)
        max_syscall_nr = 0

        with open(sys.argv[2], "w") as syscall_thunk:

            # Output a prologue consisting of header includes
            output_thunk_file_prologue(syscall_thunk)

            syscall_nr_to_thunk_table = {}
            for syscall in syscall_list:

                if syscall.nr > max_syscall_nr:
                    max_syscall_nr = syscall.nr
                
                syscall_nr_to_thunk_table[syscall.nr] = f'__sys_{syscall.name}_thunk'

                output_syscall_thunk(syscall, syscall_thunk)
            
            # Output a special thunk for nosys
            sys_nosys = Syscall("nosys", [], "int", -1)
            output_syscall_thunk(sys_nosys, syscall_thunk)

            syscall_thunk.write("\n")

            output_syscall_table(syscall_thunk, syscall_nr_to_thunk_table, max_syscall_nr)
        
        # Write a syscall.h with __NR and SYS_ defines, plus a NR_SYSCALL_MAX define
        with open(sys.argv[3], "w") as syscall_h:
            
            for syscall in syscall_list:
                syscall_h.write(f'#define __NR_{syscall.name}    {syscall.nr}\n')
            
            # SYS_ redirects to __NR_
            for syscall in syscall_list:
                syscall_h.write(f'#define SYS_{syscall.name}    __NR_{syscall.name}\n')
            
            syscall_h.write(f'#define NR_SYSCALL_MAX    {max_syscall_nr}\n')
            



if __name__ == "__main__":
    main()
