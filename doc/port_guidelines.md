# Port Guidelines

## Requirements for a port to Onyx
- ELF file support (the binary must be in ELF format)
- No use of dynamic libraries (They are not yet supported)
- No use of fancy 2D and 3D features

## Requirements for a port to be accepted in the Onyx source tree
- It *MUST* not be a really hacky patch
- It *MUST* work
- It *MUST* be legal (can't contain code used without permition)
- It *MAY* work flawlessly (Full support of something is hard to get with Hobby OS'es)
- It *MUST* not be broken software or very vulnerable software (Software that deals with system calls directly is one example)
