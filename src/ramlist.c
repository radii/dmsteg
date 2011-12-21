/* ramlist.c - memory management */
#include <stdlib.h>
#include <sched.h>
#include <signal.h>
#include <string.h>
#include "steg.h"

/* The point of this code is to clean ram before free()ing it, so as not to
 * leak secrets. The use of atexit() allows even non-free()'d ram to be cleaned
 * on program termination */

/* Allocated addresses and their sizes are stored on a stack (FILO), so most
 * steg_free() calls should be fast. Stack is realloc()'d only every
 * RAMLIST_BLOCK_ENTRIES so as not to slow things down */

#ifdef REENTRANT
	#include <pthread.h>
	pthread_mutex_t ramlist_lock;
	#define RAMLIST_INIT	pthread_mutex_init(&ramlist_lock, NULL)
	#define RAMLIST_LOCK	pthread_mutex_lock(&ramlist_lock)
	#define RAMLIST_UNLOCK	pthread_mutex_unlock(&ramlist_lock)
#else
	#define RAMLIST_INIT
	#define RAMLIST_LOCK
	#define RAMLIST_UNLOCK
#endif

#define RAMLIST_BLOCK_ENTRIES	1024
#define RAMLIST_MASK		(RAMLIST_BLOCK_ENTRIES - 1)

typedef struct {
	void *ram;
	size_t size;
} ramlist_t;

ramlist_t *ramlist = NULL;
int entries = 0;

static void wait_for_ram(void)
{
	sched_yield();
}

static void *do_realloc(void *ptr, size_t size)
{
	void *ram;
	if(!size) {
		free(ptr);
		return NULL;
	}
	while(!(ram = realloc(ptr, size))) {
		wait_for_ram();
	}
	return ram;
}

static int ramlist_find(void *ram)
{
	int i;
	for(i = entries - 1; i > -1; i--) {
		if(ramlist[i].ram == ram) {
			return i;
		}
	}
	die("ramlist_find: address not in list");
	return 0;
}

static void ramlist_add(void *ram, size_t size)
{
	RAMLIST_LOCK;
	if(!ram) {
		printf("adding 0 - u wot m8? _%zu_\n", size);
	}
	if(!(entries & RAMLIST_MASK)) {
		ramlist = do_realloc(ramlist, sizeof(ramlist_t) * (entries + RAMLIST_BLOCK_ENTRIES));
	}
	ramlist[entries].ram = ram;
	ramlist[entries++].size = size;
	RAMLIST_UNLOCK;
}

static void ramlist_remove(void *ram)
{
	RAMLIST_LOCK;
	memcpy(&ramlist[ramlist_find(ram)], &ramlist[entries - 1], sizeof(ramlist_t));
	if(!(--entries & RAMLIST_MASK)) {
		ramlist = do_realloc(ramlist, sizeof(ramlist_t) * entries);
	}
	RAMLIST_UNLOCK;
}

void steg_free(void *ram)
{
	if(ram) {
		RAMLIST_LOCK;
		memset(ram, 0, ramlist[ramlist_find(ram)].size);
		RAMLIST_UNLOCK;
		free(ram);
		ramlist_remove(ram);
	}
}

static void steg_free_all(void)
{
	while(entries) {
		steg_free(ramlist[entries - 1].ram);
	}
	free(ramlist);
}

void steg_free_args(int argc, void **argv)
{
	int i;
	for(i = 0; i < argc; i++) {
		steg_free(argv[i]);
	}
}

void clean_exit(int sig)
{
	exit(0);
}

void ramlist_init(void)
{
	struct sigaction act;
	ramlist = calloc(1, sizeof(ramlist_t));
	if(!ramlist) {
		die("calloc()");
	}
	if(atexit(steg_free_all)) {
		die("atexit()");
	}
	/* Make sure the atexit() stuff gets called on ctrl-C */
	act.sa_handler = clean_exit;
	act.sa_flags = 0;
	sigemptyset(&act.sa_mask);
	sigaction(SIGTERM, &act, NULL);
	sigaction(SIGINT, &act, NULL);
	RAMLIST_INIT;
}

void *steg_malloc(size_t size)
{
	void *ram;
	while(!(ram = malloc(size))) {
		wait_for_ram();
	}
	ramlist_add(ram, size);
	return ram;
}

void *steg_calloc(size_t n, size_t size)
{
	void *ram;
	while(!(ram = calloc(n, size))) {
		wait_for_ram();
	}
	ramlist_add(ram, size);
	return ram;
}

void *steg_realloc(void *ptr, size_t size)
{
	void *ram = do_realloc(ptr, size);
	if(ptr) {
		ramlist_remove(ptr);
	}
	if(ram) {
		ramlist_add(ram, size);
	}
	return ram;
}
