/* stegctl.c - for talking to stegd */
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include "steg.h"

int main(int argc, char **argv)
{
	int stegd, i, length;
	char *cmd, *buffer;
	if(argc < 2) {
		printf("Usage: stegctl <message to stegd>\n");
		exit(1);
	}
	stegd = stegd_connect();
	if(stegd < 0) {
		die(getuid() ? "cannot connect to stegd (probably because you are not root)" : "cannot connect to stegd");
	}
	for(length = 0, i = 1; i < argc; i++) {
		length += strlen(argv[i]);
		length++;
	}
	cmd = steg_malloc(length);
	strcpy(cmd, argv[1]);
	for(i = 2; i < argc; i++) {
		strcat(cmd, " ");
		strcat(cmd, argv[i]);
	}
	write(stegd, cmd, length);
	steg_free(cmd);
	buffer = malloc(BUFLEN);
	read(stegd, buffer, BUFLEN);
	buffer[BUFLEN - 1] = 0;
	printf("%s\n", buffer);
	close(stegd);
	if(!strncmp(buffer, MESG_STR("OK") - 1)) {
		return 0;
	} else {
		return 1;
	}
}
