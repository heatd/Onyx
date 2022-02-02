#!/bin/sh

submodule_paths=$(git submodule status | cut -f 3 -d ' ')
ignored_paths="musl kernel/acpica kernel/include/acpica libc/include sysroot usystem/out usystem/dash kernel/lib/compiler-rt kernel/lib/libfdt"

find_or=""
had_before="0"

for path in $submodule_paths $ignored_paths; do
    if [ "$had_before" = "1" ]; then
        find_or="${find_or} -o "
    else
        had_before="1"
    fi
    find_or="${find_or} -path ./$path"
done

find . \( $find_or \) -prune -o -regex '.*\.\(c\|h\|cpp\|hpp\|cc\|cxx\)' -print -exec clang-format -style=file -i {} \;

