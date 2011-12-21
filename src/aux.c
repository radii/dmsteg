/* aux.c - stuff that gets in the way */
#define _GNU_SOURCE	/* for ffsll() */
#include <stdlib.h>
#include <stdio.h>
#include <sched.h>
#include <strings.h>
#include <signal.h>
#include <string.h>
#include <sys/fcntl.h>
#include <unistd.h>
#include <errno.h>
#include "steg.h"

int default_verbosity = 1, devrandom, devurandom;

void die(char *errormsg)
{
	printf("Fatal error: %s\n", errormsg);
	exit(1);
}

int ffs64(u64 x)
{
	return ffsll(x);
}

u64 kmgt_multiply(u64 x, char *c)
{
	int i;
	char *kmg = "KkMmGgTt";
	while(*c == ' ') { c++; }
	for(i = 2; *kmg; i++) {
		if(*c == *kmg++) {
			x <<= (10 * (i >> 1));
			break;
		}
	}
	return x;
}

u64 round_up(u64 x, u64 y)
{
	return x + (x % y ? y - x % y : 0);
}

/* *dst should be bytes * 2 + 1 chars long */
void sprint_hex(char *dst, u8 *src, int bytes)
{
	int i;
	for(i = 0; i < bytes; i++) {
		sprintf(dst + i * 2, "%02x", *(u8 *)(src + i));
	}
}

/* for debugging */
void print_hex(char *name, void *src, int bytes)
{
	int i;
	printf("%s : ", name);
	for(i = 0; i < bytes; i++) {
		printf("%02x", *(u8 *)(src + i));
	}
	printf("\n");
}

int read_hex(u8 *out, char *in, int bytes)
{
	int i;
	unsigned int d;
	char tmpchars[3];
	if(strlen(in) != bytes * 2) {
		return -EINVAL;
	}
	for(i = 0; i < bytes; i++) {
		strncpy(tmpchars, &in[i * 2], 2);
		tmpchars[2] = 0;
		sscanf(tmpchars, "%2x", &d);
		out[i] = d;
	}
	return 0;
}

int _randomise(int file, void *dst, u64 n)
{
	u64 bytesread;
	u64 readerr;
	for(bytesread=0;bytesread < n; bytesread += readerr) {
		readerr = read(file, dst + bytesread, n - bytesread);
		if(readerr==-1) {
			die("reading from (u)random");
		}
	}
	return 0;
}

int randomise(void *dst, u64 n) {
	return _randomise(devrandom, dst, n);
}

int urandomise(void *dst, u64 n) {
	return _randomise(devurandom, dst, n);
}

int initialise_random()
{
	devrandom = open("/dev/random", O_RDONLY);
	if(!devrandom) {
		die("cannot open /dev/random");
	}
	devurandom = open("/dev/urandom", O_RDONLY);
	if(!devurandom) {
		die("cannot open /dev/urandom");
	}
	return 0;
}
