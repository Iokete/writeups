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

As always, we will interact with the kernel by creating a C solver. In this case we are not going to exploit a vulnerable kernel module, as we can see there is `chall.patch`:

```c
diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index 24ae8f33e5d7..e5641845ecc0 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -13030,7 +13030,7 @@ static int retrieve_ptr_limit(const struct bpf_reg_state *ptr_reg,
 static bool can_skip_alu_sanitation(const struct bpf_verifier_env *env,
 				    const struct bpf_insn *insn)
 {
-	return env->bypass_spec_v1 || BPF_SRC(insn->code) == BPF_K;
+	return true;
 }
 
 static int update_alu_sanitation_state(struct bpf_insn_aux_data *aux,
@@ -14108,7 +14108,7 @@ static bool is_safe_to_compute_dst_reg_range(struct bpf_insn *insn,
 	case BPF_LSH:
 	case BPF_RSH:
 	case BPF_ARSH:
-		return (src_is_const && src_reg->umax_value < insn_bitness);
+		return (src_reg->umax_value < insn_bitness);
 	default:
 		return false;
 	}
```

This patch implements 2 major modifications in the implementation of the Linux eBPF verifier. I will refer now (and later on) to [this blog](https://chomp.ie/Blog+Posts/Kernel+Pwning+with+eBPF+-+a+Love+Story) by chompie, that is the one I used to learn throughout the CTF about eBPF internals.

eBPF provides a way of creating and executing kernel level applications from userland as a non-privileged user. As you would think this can be dangerous, and that is the reason why eBPF implements a lot of security measures around its functionality. The verifier will analyze the program, creating a control flow graph and monitorizing the content of the registers. This will be a **static** analysis, meaning he doesn't really know the content of each register, this is the important part. It will keep track of the contents by creating specific ranges: 

From [Kernel Pwning with eBPF - a Love Story](https://chomp.ie/Blog+Posts/Kernel+Pwning+with+eBPF+-+a+Love+Story):
- ``umin_value``, ``umax_value`` store the min/max value of the register when interpreted as an unsigned (64 bit) integer
- ``smin_value``, ``smax_value`` store the min/max value of the register when interpreted as a signed (64 bit) integer.
- ``u32_min_value``, ``u32_max_value`` store the min/max value of the register when interpreted as an unsigned (32 bit) integer.
- ``s32_min_value``, ``s32_max_value`` store the min/max value of the register when interpreted as a signed (32 bit) integer.

