/* stegd.c - the steg daemon */
/* COMMAND	DESCRIPTION
 * version	returns version number
 * die		quit
 * list		list all devices known to stegd
 * rate		sets automatic shuffling rate (0 or 1)
 * shuffle	performs one shuffle on a random aspect
 * remove	removes aspect from stegd's awareness
 * test		returns path if already registered, else "OK"
 * getpath	preliminarily allocate a /dev/mapper/stegX
 * substrate	returns aspect's substrate
 * unneeded	return number of dependent aspects, or "OK" if none
 * add		registers aspect with stegd */
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <libgen.h>
#include <openssl/evp.h>
#include <libdevmapper.h>
#include <errno.h>
#include <pthread.h>
#include <semaphore.h>
#include "steg.h"

#define THREAD_STACKSIZE 65536	/* Default is 8MB - excessive */

pthread_mutex_t shuffle_lock;	/* Only one thread selecting/shuffling/bunnycalculating at a time */
	u64 next_id = 0;

pthread_attr_t pthread_attr;
sem_t create_sem;

pthread_mutex_t table_lock;	/* Protects the following: */
	steg_device_t *table = NULL;
	char **allocated_paths;
	int devices = 0;
	u64 max_id = 1;

u64 shuffle_rate = 0;

void wait_for_idle(void)
{
	sleep(1);
}

steg_device_t *get_device_from_id(u64 id)
{
	int i;
	for(i = 0; i < devices; i++) {
		if(table[i].id == id) {
			return &table[i];
		}
	}
	return NULL;
}

int bunny_set_pair(u64 id)
{
	int e = -EINVAL;
	void *data;
	steg_device_t *device;
	int bunny_level;
	u8 passphrase_hash[KEY_BYTES];
	u8 old_output[BUNNY_ENTRY_BYTES];
	u8 seed[BUNNY_ENTRY_BYTES];
	u8 output[BUNNY_ENTRY_BYTES];
	pthread_mutex_lock(&table_lock);
	if(!(device = get_device_from_id(id))) {
		goto fail;
	}
	memcpy(passphrase_hash, device->passphrase_hash, KEY_BYTES);
	memcpy(old_output, device->bunny_seed, BUNNY_ENTRY_BYTES);
	bunny_level = device->bunny_level;
	pthread_mutex_unlock(&table_lock);
	/* bunny_precalculate could take seconds, so it's done outside the table lock */
	data = bunny_precalculate(passphrase_hash, bunny_level);
	bunny_hopping(data, old_output, bunny_level, FALSE);
	urandomise(seed, BUNNY_ENTRY_BYTES);
	memcpy(output, seed, BUNNY_ENTRY_BYTES);
	bunny_hopping(data, output, bunny_level, FALSE);
	steg_free(data);
	/* Send new pair to kernel */
	pthread_mutex_lock(&table_lock);
	if(!(device = get_device_from_id(id))) {
		goto fail;
	}
	e = dm_bunnypair(device->path, old_output, seed, output);
	fail:
	pthread_mutex_unlock(&table_lock);
	return e;
}

/* Selects aspect randomly, weighted according to number of blocks in each aspect.
 * This should give every aspect the same percentage rate of rerrangement. */
u64 select_shuffle(void)
{
	int i;
	u64 blocks;
	u64 num;
	u64 id = 0;
	if(next_id) {
		return next_id;
	}
	pthread_mutex_lock(&table_lock);
	for(blocks = i = 0; i < devices; i++) {
		if(table[i].shuffling) {
			blocks += table[i].blocks;
		}
	}
	if(blocks) {
		urandomise(&num, sizeof(u64));
		num %= blocks;
		for(blocks = i = 0; i < devices; i++) {
			if(table[i].shuffling) {
				blocks += table[i].blocks;
				if(blocks > num) {
					id = table[i].id;
					goto end;
				}
			}
		}
	}
	end:
	pthread_mutex_unlock(&table_lock);
	return id;
}

int shuffle(void)
{
	u64 id;
	steg_device_t *device;
	int e = -ENODEV;
	if((id = select_shuffle())) {
		next_id = 0;		/* Mark as serviced */
		pthread_mutex_lock(&table_lock);
		if((device = get_device_from_id(id))) {
			e = dm_message(device->path, "shuffle");
		}
		pthread_mutex_unlock(&table_lock);
		if(e == -ENOKEY) {
			/* Key required for header move */
			next_id = id;
			bunny_set_pair(id);
			e = -EAGAIN;
		}
		if(e == -EPERM) {
			/* Aspect has shuffling disabled */
			pthread_mutex_lock(&table_lock);
			if((device = get_device_from_id(id))) {
				device->shuffling = 0;
			}
			pthread_mutex_unlock(&table_lock);
		}
	}
	return e;
}

void *shuffle_main_loop(void *arg)
{
	for(;;) {
		wait_for_idle();
		if(devices && shuffle_rate) {
			if(!pthread_mutex_trylock(&shuffle_lock)) {
				shuffle();
				pthread_mutex_unlock(&shuffle_lock);
			}
		}
	}
}

void free_device(int num)
{
	steg_free(table[num].path);
	steg_free(table[num].substrate);
	for(; num < devices - 1; num++) {
		memcpy(&table[num], &table[num + 1], sizeof(steg_device_t));
	}
	devices--;
	table = steg_realloc(table, sizeof(steg_device_t) * devices);
}

/* Deregisters devices that were removed without stegd's knowledge */
void clean_device_list(void)
{
	int i;
	struct stat buf;
	pthread_mutex_lock(&table_lock);
	for(i = 0; i < devices; i++) {
		if(stat(table[i].path, &buf)) {
			free_device(i--);
		}
	}
	pthread_mutex_unlock(&table_lock);
}

/* Guards against duplicate mounts - that could be very bad indeed */
char *device_registered(u8 *salt)
{
	char *path = NULL;
	int i;
	pthread_mutex_lock(&table_lock);
	for(i = 0; i < devices; i++) {
		if(!memcmp(table[i].salt, salt, SALT_BYTES)) {
			path = table[i].path;
			break;
		}
			
	}
	pthread_mutex_unlock(&table_lock);
	return path;
}

char *get_substrate(char *path)
{
	int i;
	char *substrate = NULL;
	pthread_mutex_lock(&table_lock);
	for(i = 0; i < devices; i++) {
		if(!strcmp(table[i].path, path)) {
			substrate = table[i].substrate;
		}
	}
	pthread_mutex_unlock(&table_lock);
	return substrate;
}

int device_is_needed(char *path)
{
	int i, e = 0;
	pthread_mutex_lock(&table_lock);
	for(i = 0; i < devices; i++) {
		if(!strcmp(table[i].substrate, path)) {
			e++;
		}
	}
	pthread_mutex_unlock(&table_lock);
	return e;
}

int remove_device(char *path)
{
	int i, e = -1;
	pthread_mutex_lock(&table_lock);
	for(i = 0; i < devices; i++) {
		if(!strcmp(table[i].path, path)) {
			free_device(i);
			e = 0;
			goto end;
		}
	}
	end:
	pthread_mutex_unlock(&table_lock);
	return e;
}

int add_device(char *path, char *substrate, u64 shuffling, u64 blocks, u64 block_bytes, u64 bunny_level, u8 *passphrase_hash, u8 *bunny_seed, u8 *salt)
{
	pthread_mutex_lock(&table_lock);
	table = steg_realloc(table, sizeof(steg_device_t) * (devices + 1));
	steg_device_t *d = &table[devices];
	d->id = max_id++;	/* Unique */
	d->path = steg_malloc(strlen(path) + 1);
	strcpy(d->path, path);
	d->substrate = steg_malloc(strlen(substrate) + 1);
	strcpy(d->substrate, substrate);
	d->shuffling = shuffling;
	d->blocks = blocks;
	d->block_bytes = block_bytes;
	d->bunny_level = bunny_level;
	memcpy(d->passphrase_hash, passphrase_hash, KEY_BYTES);
	memcpy(d->bunny_seed, bunny_seed, BUNNY_ENTRY_BYTES);
	memcpy(d->salt, salt, SALT_BYTES);
	devices++;
	pthread_mutex_unlock(&table_lock);
	return 0;
}

int get_ull_from_input(u64 *dst, char **saveptr)
{
	char *token;
	if(!(token = strtok_r(NULL, " ", saveptr))) {
		return -EINVAL;
	}
	errno = 0;
	*dst = strtoull(token, NULL, 10);
	if(errno) {
		return -EINVAL;
	}
	return 0;
}

int get_hex_from_input(u8 *dst, int bytes, char **saveptr)
{
	char *token;
	if(!(token = strtok_r(NULL, " ", saveptr))) {
		return -EINVAL;
	}
	if(read_hex(dst, token, bytes)) {
		return -EINVAL;
	}
	return 0;
}

/* Check:
 * 	1. path doesn't exist
 * 	2. path is not registered
 * 	3. path is not preliminarily allocated */
int alloc_path(char *path)
{
	struct stat buf;
	int i, e = 0;
	errno = 0;
	pthread_mutex_lock(&table_lock);
	stat(path, &buf);
	if(errno != ENOENT) {
		e = -EEXIST;
	}
	for(i = 0; i < devices; i++) {
		if(!strcmp(table[i].path, path)) {
			e = -EEXIST;
		}
	}
	for(i = 0; allocated_paths[i]; i++) {
		if(!strcmp(allocated_paths[i], path)) {
			e = -EEXIST;
		}
	}
	if(!e) {
		allocated_paths[i] = steg_malloc(strlen(path) + 1);
		strcpy(allocated_paths[i], path);
		allocated_paths = steg_realloc(allocated_paths, sizeof(char *) * (i + 2));
		allocated_paths[i + 1] = NULL;
	}
	pthread_mutex_unlock(&table_lock);
	return e;
}

void dealloc_path(char *path)
{
	int i;
	if(path) {
		pthread_mutex_lock(&table_lock);
		for(i = 0; allocated_paths[i]; i++) {
			if(!strcmp(allocated_paths[i], path)) {
				for(;allocated_paths[i + 1]; i++) {
					allocated_paths[i] = allocated_paths[i + 1];
				}
				allocated_paths[i] = NULL;
				break;
			}
		}
		allocated_paths = steg_realloc(allocated_paths, sizeof(char *) * (i + 1));
		pthread_mutex_unlock(&table_lock);
	}
}

void *io_handle(void *client_ptr)
{
	struct stat stat_buf;
	u64 shuffling, blocks, block_bytes, bunny_level, rate;
	char *saveptr, *path, **client_allocated_paths = NULL, *substrate, *buf = steg_malloc(BUFLEN);
	u8 passphrase_hash[KEY_BYTES];
	u8 bunny_seed[BUNNY_ENTRY_BYTES];
	u8 salt[SALT_BYTES];
	int i, e, client = *(int *)client_ptr, num_client_allocated_paths = 0;
	sem_post(&create_sem);
	while(read(client, buf, BUFLEN)) {
		buf[BUFLEN - 1] = 0;
		if(!strncmp(buf, MESG_STR("version") - 1)) {
			write(client, MESG_STR(STEGD_VERSION_STRING));
			goto next;
		}
		if(!strncmp(buf, MESG_STR("die") - 1)) {
			exit(0);
		}
		if(!strncmp(buf, MESG_STR("list") - 1)) {
			pthread_mutex_lock(&table_lock);
			for(i = 0; i < devices; i++) {
				snprintf(buf, BUFLEN, "%zu\t%i\t%s\t%s\n", table[i].id, table[i].shuffling, table[i].path, table[i].substrate);
				write(client, buf, strlen(buf));
			}
			pthread_mutex_unlock(&table_lock);
			buf[0] = 0;
			write(client, buf, 1);
			goto next;
		}
		if(!strncmp(buf, MESG_STR("rate") - 1)) {
			strtok_r(buf, " ", &saveptr);
			if(get_ull_from_input(&rate, &saveptr)) {
				goto badmessage;
			}
			if(rate > 1) {
				goto badmessage;
			}
			shuffle_rate = rate;
			goto ok;
		}
		if(!strncmp(buf, MESG_STR("shuffle") - 1)) {
			pthread_mutex_lock(&shuffle_lock);
			e = shuffle();
			if(e == -EAGAIN) {
				e = shuffle();
			}
			pthread_mutex_unlock(&shuffle_lock);
			if(!e) {
				goto ok;
			}
			if(e == -ENODEV) {
				write(client, MESG_STR("no devices ready for shuffle"));
			} else {
				write(client, MESG_STR("unknown error"));
			}
			goto next;
		}
		if(!strncmp(buf, MESG_STR("remove") - 1)) {
			strtok_r(buf, " ", &saveptr);
			if(!(path = strtok_r(NULL, " ", &saveptr))) {
				goto badmessage;
			}
			if(remove_device(path)) {
				write(client, MESG_STR("device not registered with stegd"));
				goto next;
			}
			goto ok;
		}
		if(!strncmp(buf, MESG_STR("test") - 1)) {
			strtok_r(buf, " ", &saveptr);
			if(get_hex_from_input(salt, SALT_BYTES, &saveptr)) {
				goto badmessage;
			}
			clean_device_list();
			if((path = device_registered(salt))) {
				write(client, path, strlen(path) + 1);
				goto next;
			}
			goto ok;
		}
		if(!strncmp(buf, MESG_STR("getpath") - 1)) {
			client_allocated_paths = steg_realloc(client_allocated_paths, ++num_client_allocated_paths * sizeof (char *));
			client_allocated_paths[num_client_allocated_paths - 1] = steg_malloc(128);
			clean_device_list();
			for(i = 0;; i++) {
				sprintf(client_allocated_paths[num_client_allocated_paths - 1], "/dev/mapper/steg%i", i);
				if(!alloc_path(client_allocated_paths[num_client_allocated_paths - 1])) {
					break;
				}
			}
			write(client, client_allocated_paths[num_client_allocated_paths - 1], strlen(client_allocated_paths[num_client_allocated_paths - 1]) + 1);
			goto next;
		}
		if(!strncmp(buf, MESG_STR("substrate") - 1)) {
			strtok_r(buf, " ", &saveptr);
			if(!(path = strtok_r(NULL, " ", &saveptr))) {
				goto badmessage;
			}
			if(!(substrate = get_substrate(path))) {
				write(client, MESG_STR("device not registered with stegd"));
				goto next;
			}
			write(client, substrate, strlen(substrate) + 1);
			goto next;
		}
		if(!strncmp(buf, MESG_STR("unneeded") - 1)) {
			strtok_r(buf, " ", &saveptr);
			if(!(path = strtok_r(NULL, " ", &saveptr))) {
				goto badmessage;
			}
			if(!(e = device_is_needed(path))) {
				goto ok;
			}
			sprintf(buf, "%i", e);
			write(client, buf, strlen(buf) + 1);
			goto next;
		}
		if(!strncmp(buf, MESG_STR("add") - 1)) {
			strtok_r(buf, " ", &saveptr);
			if(!(path = strtok_r(NULL, " ", &saveptr))) {
				goto badmessage;
			}
			if(stat(path, &stat_buf)) {
				write(client, MESG_STR("cannot stat device"));
				goto next;
			}
			if(!S_ISBLK(stat_buf.st_mode)) {
				write(client, MESG_STR("not a block device"));
				goto next;
			}
			if(!(stat_buf.st_mode & S_IWUSR)) {
				write(client, MESG_STR("block device is read-only"));
				goto next;
			}
			if(!(substrate = strtok_r(NULL, " ", &saveptr))) {
				goto badmessage;
			}
			if(get_ull_from_input(&shuffling, &saveptr)) {
				goto badmessage;
			}
			if(get_ull_from_input(&blocks, &saveptr)) {
				goto badmessage;
			}
			if(get_ull_from_input(&block_bytes, &saveptr)) {
				goto badmessage;
			}
			if(get_ull_from_input(&bunny_level, &saveptr)) {
				goto badmessage;
			}
			if(get_hex_from_input(passphrase_hash, KEY_BYTES, &saveptr)) {
				goto badmessage;
			}
			if(get_hex_from_input(bunny_seed, BUNNY_ENTRY_BYTES, &saveptr)) {
				goto badmessage;
			}
			if(get_hex_from_input(salt, SALT_BYTES, &saveptr)) {
				goto badmessage;
			}
			if(add_device(path, substrate, shuffling, blocks, block_bytes, bunny_level, passphrase_hash, bunny_seed, salt)) {
				write(client, MESG_STR("add device failed"));
				goto next;
			}
			goto ok;
		}
		write(client, MESG_STR("ERROR unknown command"));
		goto next;
		badmessage:
		write(client, MESG_STR("ERROR badly formed command"));
		goto next;
		ok:
		write(client, MESG_STR("OK"));
		next:;
	}
	for(i = 0; i < num_client_allocated_paths; i++) {
		dealloc_path(client_allocated_paths[i]);
	}
	steg_free(client_allocated_paths);
	close(client);
	steg_free(buf);
	pthread_exit(NULL);
}

void unlink_socket(void)
{
	unlink(STEGD_SOCKET);
}

void handle_sigpipe(int sig) { }

int main(int argc, char *argv[])
{
	struct sockaddr_un address;
	socklen_t address_length;
	struct sigaction act;
	pthread_t main_loop_thread, child_thread;
	int socket_fd, client;

	/* Misc initialisations */
	pthread_attr_init(&pthread_attr);
	pthread_attr_setstacksize(&pthread_attr, THREAD_STACKSIZE);
	if(getuid()) {
		die("not root");
	}
	if(mlockall(MCL_CURRENT | MCL_FUTURE)) {
		die("mlockall()");
	}
	ramlist_init();
	act.sa_handler = handle_sigpipe;
	act.sa_flags = 0;
	sigemptyset(&act.sa_mask);
	sigaction(SIGPIPE, &act, NULL);
	allocated_paths = steg_calloc(1, sizeof(char *));
	atexit(unlink_socket);
	dm_check_version();
	initialise_random();
	EVP_xts = EVP_STEG_CIPHER;
	pthread_mutex_init(&table_lock, NULL);
	pthread_mutex_init(&shuffle_lock, NULL);

	/* Set up the socket */
	socket_fd = socket(PF_UNIX, SOCK_STREAM, 0);
	if(socket_fd < 0) {
		die("socket()");
	}
	unlink(STEGD_SOCKET);
	memset(&address, 0, sizeof(struct sockaddr_un));
	address.sun_family = AF_UNIX;
	strcpy(address.sun_path, STEGD_SOCKET);
	if(bind(socket_fd, (struct sockaddr *)&address, sizeof(struct sockaddr_un))) {
		die("bind()");
	}
	chmod(STEGD_SOCKET, S_IRUSR|S_IWUSR);
	if(listen(socket_fd, 4)) {
		die("listen()");
	}
	/* All good; set the main loop going, daemonise and handle incoming I/O */
	if(pthread_create(&main_loop_thread, &pthread_attr, shuffle_main_loop, "")) {
		die("pthread_create()");
	}
	daemon(0, 0);
	while((client = accept(socket_fd, (struct sockaddr *)&address, &address_length)) > -1) {
		sem_init(&create_sem, 0, 0);
		if(pthread_create(&child_thread, &pthread_attr, &io_handle, &client)) {
			die("pthread_create()");
		}
		pthread_detach(child_thread);
		/* Wait for child to finish with the client integer */
		sem_wait(&create_sem);
	}
	close(socket_fd);
	unlink(STEGD_SOCKET);
	return 0;
}
