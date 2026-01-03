# kerbab

## TL;DR
- Convert an off-by-null vulnerability into a off-by-one in SLUB to overwrite current->thread_info.flags to disable SECCOMP and read the flag
