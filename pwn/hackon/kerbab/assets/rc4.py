from Crypto.Cipher import ARC4
from pwn import *

def brute(b: int):
    for i in range(0xfff):
        key = p16(i) 
        length = 1
        cipher = ARC4.new(key)
        buf = b'A' * 16 + b'\x00'
        msg = cipher.encrypt(buf)
        if msg[16] == b:
            c_arr = ", ".join([f"0x{b:02x}" for b in key])
            print("static char key_buf[MAX_RC4_LEN] = {", c_arr, " };")

brute(0x40)
