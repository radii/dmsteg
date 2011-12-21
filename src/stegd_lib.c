/* stegd_lib.c - for interfacing to stegd */
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <errno.h>
#include "steg.h"

int stegd_connect(void)
{
	struct sockaddr_un address;
	int stegd;
	char *buffer;
	stegd = socket(PF_UNIX, SOCK_STREAM, 0);
	if(stegd < 0) {
		return -errno;
	}
	memset(&address, 0, sizeof(struct sockaddr_un));
	address.sun_family = AF_UNIX;
	strcpy(address.sun_path, STEGD_SOCKET);
	if(connect(stegd, (struct sockaddr *)&address, sizeof(struct sockaddr_un))) {
		return -errno;
	}
	write(stegd, MESG_STR("version"));
	buffer = steg_malloc(BUFLEN);
	read(stegd, buffer, BUFLEN);
	buffer[BUFLEN - 1] = 0;
	if(strncmp(buffer, MESG_STR(STEGD_VERSION_STRING))) {
		die("unknown stegd version");
	}
	steg_free(buffer);
	return stegd;
}

/* Is aspect already mounted? */
char *stegd_test(int stegd, u8 *salt)
{
	char *cmd = steg_malloc(sizeof("test ") + SALT_BYTES * 2);
	char *buffer = steg_malloc(BUFLEN);
	strcpy(cmd, "test ");
	sprint_hex(cmd + strlen(cmd), salt, SALT_BYTES);
	write(stegd, cmd, strlen(cmd) + 1);
	read(stegd, buffer, BUFLEN);
	buffer[BUFLEN - 1] = 0;
	if(!strncmp(buffer, MESG_STR("OK") - 1)) {
		steg_free(buffer);
		buffer = NULL;
	} else {
		if(!strncmp(buffer, MESG_STR("ERROR") - 1)) {
			printf("stegd_test(): %s\n", buffer);
			exit(1);
		} else {
			buffer = steg_realloc(buffer, strlen(buffer) + 1);
		}
	}
	steg_free(cmd);
	return buffer;
}

/* stegd manages /dev/mapper/steg* allocation */
char *stegd_get_path(int stegd)
{
	char *buffer;
	if(write(stegd, MESG_STR("getpath")) == -1) {
		return NULL;
	}
	buffer = steg_malloc(BUFLEN);
	if(read(stegd, buffer, BUFLEN) == -1) {
		goto fail;
	}
	if(!strncmp(buffer, MESG_STR("ERROR") - 1)) {
		goto fail;
	}
	buffer[BUFLEN - 1] = 0;
	return steg_realloc(buffer, strlen(buffer) + 1);
	fail:
	steg_free(buffer);
	return NULL;
}

int stegd_add(int stegd, aspect_t *a, char *path)
{
	int e = 0;
	char *cmd = steg_malloc(strlen(path) + strlen(a->substrate->filename) + 1024);
	char *buffer = steg_malloc(BUFLEN);
	strcpy(cmd, "add ");
	strcat(cmd, path);
	strcat(cmd, " ");
	strcat(cmd, a->substrate->filename);
	sprintf(cmd + strlen(cmd), " %zu %zu %zu %i ", a->shuffling, a->blocks, a->block_bytes, a->bunny_level);
	sprint_hex(cmd + strlen(cmd), a->passphrase_hash, KEY_BYTES);
	strcat(cmd, " ");
	sprint_hex(cmd + strlen(cmd), a->bunny_seed, BUNNY_ENTRY_BYTES);
	strcat(cmd, " ");
	sprint_hex(cmd + strlen(cmd), a->salt, SALT_BYTES);
	write(stegd, cmd, strlen(cmd) + 1);
	read(stegd, buffer, BUFLEN);
	buffer[BUFLEN - 1] = 0;
	if(strncmp(buffer, MESG_STR("OK") - 1)) {
		e = -EIO;
	}
	steg_free(buffer);
	steg_free(cmd);
	return e;
}
