# Days Gone 

## TL;DR
- entry level kernel challenge, abuse UAF to overwrite ``weapon->attack_func`` pointer with ``commit_creds(prepare_kernel_cred(0))`` (win function)  

## Challenge Description

> Create a poc that exploits the kernel driver to gain root access and write a file to root directory. The poc should include your source code and a binary that exploits the vulnerability.

- Category: **mobile**

## Exploitation
### Analyzing the source code


### Exploiting the vulnerability


### Getting the flag