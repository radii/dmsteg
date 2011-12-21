/* file.c - block device/file I/O stuff */
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <linux/fs.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <openssl/evp.h>
#include <errno.h>
#include "steg.h"

substrate_t *open_substrate(char *filename)
{
	struct stat buf;
	substrate_t *substrate = steg_calloc(1, sizeof(substrate_t));
	substrate->filename = steg_malloc(strlen(filename) + 1);
	strcpy(substrate->filename, filename);
	if(stat(substrate->filename, &buf)) {
		printf("\tError opening %s\n", substrate->filename);
		steg_free(substrate->filename);
		steg_free(substrate);
		return NULL;
	}
	if(S_ISBLK(buf.st_mode)) {
		substrate->is_block_device = 1;
	} else {
		if(!S_ISREG(buf.st_mode)) {
			die("not a block device and not a file");
		}
	}
	if((substrate->handle = open(substrate->filename, O_RDWR, 0))==-1) {
		if(errno == EACCES) {
			printf("\topen(): EACCES (permission denied)\n");
		}
		die("Opening file/device");
	}
	if(substrate->is_block_device) {
		if(ioctl(substrate->handle, BLKGETSIZE64, &substrate->bytes)==-1) {
			die("ioctl");
		}

	} else {
		substrate->bytes = buf.st_size;
	}
	if(substrate->bytes < MINIMUM_BLOCK_BYTES * 4) {
		die("substrate too small");
	}
	return substrate;
}

int read_data_from_file(int handle, u64 bytes, void *data)
{
	u64 done_bytes, readerr;
	for(done_bytes = 0; done_bytes < bytes; done_bytes += readerr)
	{
		readerr = read(handle, data + done_bytes, bytes - done_bytes);
		if(readerr==-1) {
			return -errno;
		}
	}
	return 0;
}

int read_sectors(substrate_t *substrate, u64 offset, u64 bytes, void *data)
{
	if(offset + bytes > substrate->bytes) {
		die("read_sectors: read past end of device");
	}
	if(offset & 0x1ff) {
		die("read_sectors: offset not at sector boundary");
	}
	if(bytes & 0x1ff) {
		die("read_sectors: bytes not a multiple of sector size");
	}
	if(substrate->aspect) {
		return read_data_from_aspect(substrate->aspect, substrate->aspect->block, offset, bytes, data);
	} else {
		if(lseek(substrate->handle, offset, SEEK_SET)==-1) {
			die ("lseek");
		}
		return read_data_from_file(substrate->handle, bytes, data);
	}
}

int write_data_to_file(int handle, u64 bytes, void *data)
{
	u64 done_bytes;
	u64 writeerr;
	for(done_bytes = 0; done_bytes < bytes; done_bytes += writeerr)
	{
		writeerr = write(handle, data + done_bytes, bytes - done_bytes);
		if(writeerr==-1) {
			return -errno;
		}
	}
	return 0;
}

int write_sectors(substrate_t *substrate, u64 offset, u64 bytes, void *data)
{
	if(offset + bytes > substrate->bytes) {
		die("write_sectors: write past end of device");
	}
	if(offset & 0x1ff) {
		die("write_sectors: offset not at sector boundary");
	}
	if(bytes & 0x1ff) {
		die("write_sectors: bytes not a multiple of sector size");
	}
	if(substrate->aspect) {
		return write_data_to_aspect(substrate->aspect, substrate->aspect->block, offset, bytes, data);
	} else {
		if(lseek(substrate->handle, offset, SEEK_SET)==-1) {
			die ("lseek");
		}
		return write_data_to_file(substrate->handle, bytes, data);
	}
}

int read_sector(substrate_t *substrate, u64 offset, void *data)
{
	return read_sectors(substrate, offset, SECTOR_BYTES, data);
}

int write_sector(substrate_t *substrate, u64 offset, void *data)
{
	return write_sectors(substrate, offset, SECTOR_BYTES, data);
}

/* index should be a->header_block, a->index_block, or a->block */
/* offset in bytes from start of specified block(s) */
int encrypt_and_write_atom(aspect_t *a, block_t *index, u64 offset, void *plaintext)
{
	u8 key[KEY_BYTES];
	steg_cipher_ctx ctx;
	int e;
	void *ciphertext;
	if(a->encryption) {
		ciphertext = steg_malloc(a->atom_bytes);
		get_data_atom_key(a, offset, key);
		steg_cipher_init(&ctx, key, ENCRYPT);
		steg_cipher(&ctx, ciphertext, plaintext, a->atom_bytes);
		steg_cipher_ctx_cleanup(&ctx);
		e = write_sectors(a->substrate, get_offset_from_offset(a, offset), a->atom_bytes, ciphertext);
		steg_free(ciphertext);
	} else {
		e = write_sectors(a->substrate, get_offset_from_offset(a, offset), a->atom_bytes, plaintext);
	}
	return e;
}

/* will cross atom and block boundaries. last atom will be padded with urandom, if necessary */
int write_data_to_aspect(aspect_t *a, block_t *index, u64 start, u64 bytes_to_write, void *data)
{
	u64 bytes_in_this_atom, bytes_done;
	void *leftovers;
	int e;
	for(bytes_done = 0; bytes_to_write; bytes_to_write -= bytes_in_this_atom) {
		if(bytes_to_write > a->atom_bytes) {
			bytes_in_this_atom = a->atom_bytes;
			e = encrypt_and_write_atom(a, index, start + bytes_done, data + bytes_done);
		} else {
			bytes_in_this_atom = bytes_to_write;
			leftovers = steg_malloc(a->atom_bytes);
			memcpy(leftovers, data + bytes_done, bytes_in_this_atom);
			urandomise(leftovers + bytes_in_this_atom, a->atom_bytes - bytes_in_this_atom);
			e = encrypt_and_write_atom(a, index, start + bytes_done, leftovers);
			steg_free(leftovers);
		}
		bytes_done += bytes_in_this_atom;
		if(e) {
			return e;
		}
	}
	return 0;
}

int read_and_decrypt_atom(aspect_t *a, block_t *index, u64 offset, void *plaintext)
{
	u8 key[KEY_BYTES];
	steg_cipher_ctx ctx;
	int e;
	void *ciphertext;
	if(a->encryption) {
		ciphertext = steg_malloc(a->atom_bytes);
		e = read_sectors(a->substrate, get_offset_from_offset(a, offset), a->atom_bytes, ciphertext);
		if(!e) {
			get_data_atom_key(a, offset, key);
			steg_cipher_init(&ctx, key, DECRYPT);
			steg_cipher(&ctx, plaintext, ciphertext, a->atom_bytes);
			steg_cipher_ctx_cleanup(&ctx);
		}
		steg_free(ciphertext);
	} else {
		e = read_sectors(a->substrate, get_offset_from_offset(a, offset), a->atom_bytes, plaintext);
	}
	return e;
}

int read_data_from_aspect(aspect_t *a, block_t *index, u64 start, u64 bytes_to_read, void *data)
{
	u64 bytes_in_this_atom, bytes_done;
	void *leftovers;
	for(bytes_done = 0; bytes_to_read; bytes_to_read -= bytes_in_this_atom) {
		if(bytes_to_read >= a->atom_bytes) {
			bytes_in_this_atom = a->atom_bytes;
			read_and_decrypt_atom(a, index, start + bytes_done, data + bytes_done);
		} else {
			bytes_in_this_atom = bytes_to_read;
			leftovers = steg_malloc(a->atom_bytes);
			read_and_decrypt_atom(a, index, start + bytes_done, leftovers);
			memcpy(data + bytes_done, leftovers, bytes_in_this_atom);
			steg_free(leftovers);
		}
		bytes_done += bytes_in_this_atom;
	}
	return 0;
}

int open_image(char *filename, struct stat *buf, int flags)
{
	int handle;
	if(flags == O_RDONLY) {
		handle = open(filename, flags);
	} else {
		handle = open(filename, flags, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
	}
	if(handle != -1 && buf != NULL) {
		fstat(handle, buf);
	}
	return handle;
}

int file_import_export(int exporting, aspect_t *a, char *filename)
{
	struct stat buf;
	u64 bytes_done, bytes_in_chunk, bytes_left;
	void *chunk = steg_malloc(CHUNK_BYTES);
	int image_handle = open_image(filename, &buf, exporting ? O_WRONLY | O_CREAT | O_TRUNC : O_RDONLY);
	if(image_handle == -1) {
		return -EIO;
	}
	for(bytes_done = 0; bytes_done < a->bytes; bytes_done += bytes_in_chunk) {
		bytes_left = a->bytes - bytes_done;
		bytes_in_chunk = CHUNK_BYTES;
		if(bytes_in_chunk > bytes_left) {
			bytes_in_chunk = bytes_left;
		}
		if(exporting) {
			read_data_from_aspect(a, a->block, bytes_done, bytes_in_chunk, chunk);
			write_data_to_file(image_handle, bytes_in_chunk, chunk);
		} else {
			read_data_from_file(image_handle, bytes_in_chunk, chunk);
			write_data_to_aspect(a, a->block, bytes_done, bytes_in_chunk, chunk);
		}
	}
	close(image_handle);
	steg_free(chunk);
	return 0;
}
