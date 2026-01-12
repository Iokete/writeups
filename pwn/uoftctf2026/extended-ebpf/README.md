# extended eBPF

## TL; DR

Take advantage of a vulnerable eBPF verifier patch to abuse a vulnerability in the LSH implementation to create a confusion register and leverage an OOB read/write to LPE with ALU sanitation disabled

## Challenge Description

This challenge was part of UofTCTF 2026.

> I extended the eBPF because its cool.

- Category: **pwn**

## Exploitation
### Initial setup
We are given a list of common files in kernel exploitation challenges:

```console
root@ubuntu:/home/lkt/Desktop/ctf/uoftctf/eebpf# ls -l
total 19740
-rw-r--r-- 1 root root  7480320 ene  4 08:58 bzImage
-rw-r--r-- 1 root root      798 ene  4 08:54 chall.patch
-rw-r--r-- 1 root root      547 dic 31 03:10 Dockerfile
-rw-r--r-- 1 root root  2665855 dic 31 03:10 initramfs.cpio.gz
-rwxr-xr-x 1 root root      267 dic 31 03:17 start-qemu.sh
```