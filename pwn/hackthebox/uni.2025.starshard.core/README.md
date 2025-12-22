# Starshard Core

## TL;DR
- UAF after `fopen()` leads to ``_IO_wide_data`` struct vtable hijack to call an arbitrary function 

## Challenge Description

> This challenge is part of **HackTheBox University CTF 2025: Tinsel Trouble**

- Category: **pwn**

## Exploitation
### Analyzing the source code

- When we execute the program we are asked for a name and after sending an input we are welcomed with a menu: 

```console
          ____
       .-" +' "-.
      /.'.'A_'*`.\
     |:.*'/\\-\.':|
     |:.'.||"|.'*:|
      \:~^~^~^~^:/
       /`-....-'\
      /          \
      `-.,____,.-'

Tinselwick Tinkerer Name: aaa
=== Welcome aaa — Starshard Console ===

[1] Arm Starshard Routine
[2] Attach Wish-Script Fragment
[3] Cancel Routine
[4] Commit Routine
[5] Quit
> 
```

- The binary has a function defined for each option, and works with an user-defined struct called `console_state`.

```c
typedef struct {
    char[16]    tinkerer_name   
    char[24]    spell_name  
    FILE *      core_log    
    char *      spell_fragment  
    size_t      fragment_sz
} console_state;
```

1. `arm_routine`: uses `fopen` to open a file ``starshard_core.txt``, saves it globally to `console_state.core_log`, then asks for a spell name, stores it in ``console_state.spell_name`` buffer and prints it to stdout.

2. `feed_fragment`: before doing anything, checks if global `console_state.core_log` is not ``NULL``, then initializes the spell data by setting both `fragment_sz` and `spell_fragment` to 0. Then the program asks for `ulong fragment_sz` up to 0x1f4 bytes and allocates space in the heap for the spell using `malloc(fragment_sz)` stores the pointer in `spell_fragment` and takes input safely with ``fgets()`` into the pointer.

3. `cancel_routine`: simply does `fclose(console_state.core_log)` if `console_state.core_log != NULL`.

4. `commit_routine`: populates the file `console_state.core_log` with the data from `console_state.spell_fragment`.


### Exploiting the vulnerability


### Getting the flag