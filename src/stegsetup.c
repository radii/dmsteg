/* stegsetup.c - for compiling the aspect mounting utility */
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <libdevmapper.h>
#include <errno.h>
#include <string.h>
#include "steg.h"

int logfile = -1;

/* Performs sanity checks, and cleans journal */
int check_aspect_meta_data(aspect_t *a)
{
	int e = -EIO;
	u8 hash[32];
	steg_cipher_ctx ctx;
	void *ciphertext = steg_malloc(MINIMUM_ATOM_BYTES);
	aspect_disk_header_t *header = steg_malloc(sizeof(*header));
	if(read_sector(a->substrate, get_offset(a, a->header_block), ciphertext)) {
		goto end;
	}
	steg_cipher_init(&ctx, a->header_key, DECRYPT);
	steg_cipher(&ctx, (void *)header, ciphertext + BUNNY_ENTRY_BYTES, sizeof(*header));
	SHA256((u8 *)header, sizeof(*header) - 32, hash);
	if(memcmp(hash, header->inner_hash, 32)) {
		printf("\tError: Header not where it thinks it is\n");
		goto end;
	}
	verbose_printf("\tChecking aspect %s meta data...\n", a->name);
	if(load_aspect_keyfrags(a)) {
		printf("\tLoading keyfrags failed\n");
		goto end;
	}
	if(load_aspect_index_table(a)) {
		printf("\tLoading index table failed\n");
		goto end;
	}
	if((e = load_aspect_journal(a))) {
		if(e == -EUCLEAN) {
			if(write_aspect_journal_atom(a)) {
				printf("\tFailed to write clean journal\n");
				e = -EIO;
				goto end;
			}
			fsync(a->substrate->handle);
			e = 0;
		} else {
			printf("\tLoading journal failed\n");
			goto end;
		}
	}
	e = 0;
	end:
	steg_free(a->journal);
	steg_free(a->block);
	steg_free(header);
	steg_free(ciphertext);
	return e;
}

char *mount_aspect(int stegd, aspect_t *a)
{
	char *path, *name;
	int child, status;
	if(!(path = stegd_get_path(stegd))) {
		printf("\tError: stegd_get_path()\n");
		goto fail;
	}
	/* basename(): */
	for(name = &path[strlen(path)]; *name != '/'; name--) {
		if(name < path) {
			printf("\tError: stegd returned bad path\n");
			goto fail;
		}
	}
	name++;
	/* No idea why, but /dev/mapper/stegX is not actually created until creating process exits.
	 * The workaround is to do DM_DEVICE_CREATE in a child process */
	if(!(child = fork())) {
		exit(dm_mount_aspect(a->substrate, get_offset(a, a->header_block), a->header_key, name));
	}
	if(child == -1) {
		die("fork()\n");
	}
	while(wait(&status) != child) { }
	if(!WIFEXITED(status) || WEXITSTATUS(status)) {
		printf("\tdm_mount_aspect() failed\n");
		goto fail;
	}
	/* Aspect mounted, so tell stegd about it */
	if(stegd_add(stegd, a, path)) {
		printf("\tError: stegd_add()\n");
		goto fail;
	}
	return path;
	fail:
	steg_free(path);
	return NULL;
}

int mount_aspects(substrate_t *substrate, u8 *passphrase_hash, int stegd)
{
	aspect_t **a;
	char *path, **mounted_paths;
	int e = 0, i, aspects, aspects_created = 0;
	if(!(a = load_aspects_headers(substrate, passphrase_hash, 0, DEFAULT_MAX_LEVEL, DEFAULT_MAX_TRIES))) {
		printf("\terror loading aspects header(s)\n");
		return -EINVAL;
	}
	for(i = 0; a[i]; i++) { } aspects = i;
	mounted_paths = steg_calloc(aspects, sizeof(char *));
	for(i = 0; a[i]; i++) {
		/* Ask stegd if aspect is setup already. Shuffling a doubly-
		 * mounted aspect could destroy it, so avoid at all costs */
		if(!(path = stegd_test(stegd, a[i]->salt))) {
			a[i]->substrate = substrate;
			if(check_aspect_meta_data(a[i])) {
				printf("\tAspect %s sanity checks failed\n", a[i]->name);
				goto fail;
			}
			if(!(path = mount_aspect(stegd, a[i]))) {
				printf("\tFailed to mount aspect %s\n", a[i]->name);
				goto fail;
			}
			printf("\tCreated: %s\n", path);
			aspects_created++;
			if(logfile != -1) {
				write(logfile, path, strlen(path));
				write(logfile, "\n", 1);
			}
			mounted_paths[i] = steg_malloc(strlen(path) + 1);
			strcpy(mounted_paths[i], path);
		} else {
			if(aspects_created) {
				printf("\tWarning: Aspect already setup but its substrate is not!\n");
			}
		}
		close(substrate->handle);
		steg_free(substrate->filename);
		steg_free(substrate);
		if(a[i + 1]) {
			if(!(substrate = open_substrate(path))) {
				printf("\tFailed to open %s\n", path);
				goto fail_no_free_substrate;
			}
		}
		steg_free(path);
	}
	ok:
	for(i = 0; i < aspects; i++) {
		steg_free(a[i]->atom_keyfrag);
		steg_free(a[i]);
		steg_free(mounted_paths[i]);
	}
	steg_free(mounted_paths);
	if(!e && !aspects_created) {
		printf("\tError: stegd reports all aspects setup already.\n");
		return -EINVAL;
	}
	return e;
	fail:
	close(substrate->handle);
	steg_free(substrate->filename);
	steg_free(substrate);
	fail_no_free_substrate:
	steg_free(path);
	for(i = aspects - 1; i > -1; i--) {
		if(mounted_paths[i]) {
			printf("\tUnmounting %s\n", mounted_paths[i]);
			dm_umount_aspect(mounted_paths[i]);
		}
	}
	e = - EIO;
	goto ok;
}

int main(int argc, char *argv[])
{
	u8 passphrase_hash[KEY_BYTES];
	substrate_t *substrate;
	int stegd, e;
	if(argc<2) {
		printf("Usage: %s <device/file>\n", argv[0]);
		return 1;
	}
	if(getuid()) {
		die("not root");
	}
	if(mlockall(MCL_CURRENT | MCL_FUTURE)) {
		die("mlockall()");
	}
	ramlist_init();
	initialise_random();
	EVP_xts = EVP_STEG_CIPHER;
	dm_check_version();
	/* Open underlying block device */
	if(!(substrate = open_substrate(argv[1]))) {
		return 1;
	}
	if(!substrate->is_block_device) {
		die("stegsetup requires a block device");
	}
	if(argc == 3) {
		logfile = open(argv[2], O_WRONLY | O_TRUNC, 0);
	}
	get_key_hash(passphrase_hash);
	/* Hook up with stegd; keep connection while we try to mount aspect(s) */
	stegd = stegd_connect();
	if(stegd < 0) {
		die("cannot connect to stegd");
	}
	e = mount_aspects(substrate, passphrase_hash, stegd);
	close(stegd);
	if(!e) {
		printf("stegsetup succeeded.\n");
	}
	if(logfile != -1) {
		close(logfile);
	}
	return e ? 1 : 0;
}
