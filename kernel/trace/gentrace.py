#!/bin/python3
# Copyright (c) 2023 Pedro Falcato
# This file is part of Onyx, and is released under the terms of the MIT License
# check LICENSE at the root directory for more information
#
# SPDX-License-Identifier: MIT
#
import json
import sys
from typing import TextIO
from typing import List

class TraceEvent:
    def __init__(self, name: str, category: str, args: list, format: dict):
        self.name = name
        self.category = category
        self.args = args
        self.format: dict = format
    
    def trace_event_struct_name(self) -> str:
        return f"__trace_event_{self.name}_{self.category}"

    def calculate_format(self) -> str:
        # The trace event's format describes the format to consumers
        # It may vary based on options set by the consumer itself, such as
        # timing, etc.
        # The format itself is more or less inspired by linux, but simplified.
        # We assume all records are packed (i.e no alignment), types are strong.
        # At the moment, these share a common header:
        # 1) u32 event type
        # 2) u16 record size
        # 3) u32 cpu (may change)
        # 4) u64 timestamp (depending if TIME is enabled)
        format = "field:u32 evtype;\\nfield: u16 size;\\nfield:u32 cpu;\\nfield: u64 ts; cond: TIME\\n";

        for name, format_elem in self.format.items():
            print(format_elem)
            line = f"field:{format_elem['type']} {name};"
            if format_elem.get("cond") != None:
                line += " cond: " + format_elem["cond"] + ";"
            line += "\\n"
            format += line

        return format

    def output_trace_record_struct(self, file: TextIO):
        file.write(f"DEFINE_STATIC_KEY_FALSE({self.trace_event_struct_name()}_key);\n")
        file.write(f"__tracing_section struct trace_event {self.trace_event_struct_name()} = {{\n")
        file.write(f"\t.name = \"{self.name}\",\n")
        file.write(f"\t.category = \"{self.category}\",\n")
        file.write(f"\t.format = \"{self.calculate_format()}\",\n")
        file.write(f"\t.key = &{self.trace_event_struct_name()}_key\n")
        file.write("};\n");

    def output_format_struct(self, file: TextIO):
        format = self.calculate_format()
        lines = format.split("\\n")

        file.write(f"struct {self.trace_event_struct_name()}_record {{\n")

        for line in lines:
            if len(line.strip()) == 0:
                continue
            field_start = line.find("field:") + 6
            field_end = line.find(";", field_start)
            name = line[field_start:field_end].strip()
            components = name.split()
            name = components[1]
            type = components[0]

            if type.endswith("]"):
                # Array, fixup the name and type
                arr_ind = type.find("[")
                name += type[arr_ind:]
                type = type[:arr_ind]
            file.write(f"\t{type} {name};\n")
        file.write("} __attribute__ ((packed));\n")

    def output_trace_func(self, file: TextIO):
        file.write(f"void __trace_{self.category}_{self.name}(");
        first_arg = True
        for arg in self.args:
            if not first_arg:
                file.write(',')
            file.write(f"{arg['type']} {arg['name']}");
            first_arg = False
        
        # Hacky way to see if the current trace event is a duration event
        duration_ev = len(self.args) > 0 and self.args[0]["name"] == "ts"

        # (terse name for trace_event_struct_name)
        tesn = self.trace_event_struct_name()
        file.write(")\n{\n")
        file.write(f"\tif (!({tesn}.flags & TRACE_EVENT_ENABLED)) [[likely]] return;\n\n")
        file.write(f"\tstruct {tesn}_record record = {{}};\n")
        file.write(f"\trecord.evtype = {tesn}.evid;\n")
        if not duration_ev:
            file.write(f"\tif ({tesn}.flags & TRACE_EVENT_TIME)\n\t\trecord.ts = clocksource_get_time();\n\n")
        else:
            file.write(f"\tif ({tesn}.flags & TRACE_EVENT_TIME)\n\t\t{{record.ts = ts; record.end_ts = clocksource_get_time();}}\n\n")
        file.write(f"\trecord.cpu = get_cpu_nr();\n")
        file.write("\trecord.size = sizeof(record);\n")
        print(self.format)
        for arg, arg_ in self.format.items():
            if arg == "ts":
                continue # Skip, already dealt with
            found_arg = False
            
            if arg_.get("custom_assign") != None:
                file.write(f"\t{arg_['custom_assign']}")
            else:
                for a in self.args:
                    if a["name"] == arg:
                        file.write(f"\trecord.{arg} = {arg};\n")
                        found_arg = True
                        break

        file.write("\t__trace_write((u8*) &record, sizeof(record));\n")
        file.write("}\n")

    def output_header(self, file: TextIO):
        file.write("\n")
        tesn = self.trace_event_struct_name()
        file.write(f"extern struct trace_event {tesn};\n")
        file.write(f"extern struct static_key {tesn}_key;\n\n")
        # The trace func
        file.write(f"void __trace_{self.category}_{self.name}(")
        first_arg = True
        for arg in self.args:
            if not first_arg:
                file.write(',')
            file.write(f"{arg['type']} {arg['name']}");
            first_arg = False

        file.write(");\n")

        file.write(f"__always_inline void trace_{self.category}_{self.name}(")
        first_arg = True
        for arg in self.args:
            if not first_arg:
                file.write(',')
            file.write(f"{arg['type']} {arg['name']}");
            first_arg = False

        file.write(")\n{\n")
        file.write(f"\tif (static_branch_unlikely(&{tesn}_key))\n")
        file.write(f"\t\t__trace_{self.category}_{self.name}(")
        first_arg = True
        for arg in self.args:
            if not first_arg:
                file.write(',')
            file.write(arg['name'])
            first_arg = False
        file.write(");\n}\n\n")

        file.write(f"static inline bool trace_{self.category}_{self.name}_enabled()\n{{\n")
        file.write(f"\tif (static_branch_unlikely(&{tesn}_key))\n")
        file.write(f"\t\treturn {tesn}.flags & TRACE_EVENT_ENABLED;\n")
        file.write(f"\treturn false;\n}}\n")
        



def generate_trace(trace_desc_file: TextIO, trace_header: TextIO, trace_source: TextIO):
    trace_desc = json.loads(trace_desc_file.read())
    events: List[TraceEvent] = []

    for elem in trace_desc:
        events.append(TraceEvent(elem["name"], elem["category"], elem["args"], elem["format"]))

    hdr_guard = trace_desc[0]['category']
    trace_header.write(f"//clang-format off\n#ifndef _TRACE_{hdr_guard}_H\n#define _TRACE_{hdr_guard}_H\n\n#include <onyx/trace/trace_base.h>\n#include <onyx/static_key.h>\n\n")
    trace_source.write("// clang-format off\n#include <onyx/trace/trace_base.h>\n#include <onyx/static_key.h>\n")
    for elem in events:
        elem.output_trace_record_struct(trace_source)
        trace_source.write("\n")
        elem.output_format_struct(trace_source)
        trace_source.write("\n")
        elem.output_trace_func(trace_source)

        elem.output_header(trace_header)
    
    trace_header.write("\n#endif\n")

def main():
    with open(sys.argv[1], "r") as trace_desc:
        with open(sys.argv[2], "w") as trace_header:
            with open(sys.argv[3], "w") as trace_source:
                generate_trace(trace_desc, trace_header, trace_source)

if __name__ == "__main__":
    main()
