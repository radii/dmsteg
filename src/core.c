/* core.c - the core functions */
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <errno.h>
#include "steg.h"

/* Keyfrag number for given offset (within any index) */
keyfrag_t *get_keyfrag_for_offset(aspect_t *a, u64 offset)
{
	return &a->atom_keyfrag[(offset % a->block_bytes) / a->atom_bytes];
}

/* Returns offset within header block where a keyfrag is stored */
u64 get_offset_of_keyfrag(aspect_t *a, u64 keyfrag)
{
	return a->keyfrags_offset + (sizeof(keyfrag_t) * keyfrag) + (sizeof(meta_tail_t) * (keyfrag / a->block_t_per_meta_atom));
}

void set_offset(aspect_t *a, block_t *b, u64 offset)
{
	b->offset &= ~a->offset_mask;
	b->offset |= htole64(offset);
}

u64 get_offset(aspect_t *a, block_t *b)
{
	return le64toh(b->offset & a->offset_mask);
}

/* Resolves from offset within exported space to offset on underlying device */
u64 get_offset_from_offset(aspect_t *a, u64 offset)
{
	return get_offset(a, &a->block[offset / a->block_bytes]) + (offset % a->block_bytes);
}

/* Resolves offset on underlying device to offset within aspect's exported space */
u64 get_offset_reverse(aspect_t *a, u64 offset)
{
	int i;
	for(i = 0; i < a->blocks; i++) {
		if(get_offset(a, &a->block[i]) == (offset & a->offset_mask)) {
			return i * a->block_bytes + (offset & (~a->offset_mask));
		}
	}
	return -1;
}

/* Finds keyfrag needed to load all other keyfrags */
u64 get_seed_keyfrag(aspect_t *a)
{
	u64 tmp;
	u64 keyfrag;
	u64 offset = 0;
	do {
		tmp = offset;
		keyfrag = (offset % a->block_bytes) / a->atom_bytes;
		offset = get_offset_of_keyfrag(a, keyfrag);
	} while(offset != tmp);
	return keyfrag;
}

/* Generates the plaintext for everything inside the encrypted region of the header */
aspect_disk_header_t *setup_disk_header(aspect_t *a)
{
	aspect_disk_header_t *header = steg_malloc(sizeof(*header));
	urandomise((void *)header, sizeof(*header));

	header->version = htole64(ASPECT_HEADER_VERSION);
	header->sequence = htole64(a->sequence);
	header->blocks = htole64(a->blocks);
	header->block_bytes = htole64(a->block_bytes);
	header->atom_bytes = htole64(a->atom_bytes);
	header->encryption = htole64(a->encryption);
	header->shuffling = htole64(a->shuffling);
	header->journalling = htole64(a->journalling);
	header->journal_offset = htole64(a->journal_offset);
	header->keyfrags_offset = htole64(a->keyfrags_offset);
	header->index_offset = htole64(a->index_offset);
	header->parent_level = htole64(a->parent_level);
	memcpy(header->parent_passphrase_hash, a->parent_passphrase_hash, KEY_BYTES);
	memcpy(&header->header_block_data, &a->header_block_data, KEY_BYTES);
	/* This keyfrag is all that is required for loading the rest */
	memcpy(&header->seed_keyfrag, &a->atom_keyfrag[get_seed_keyfrag(a)], KEY_BYTES);
	memcpy(header->salt, a->salt, SALT_BYTES);
	strcpy(header->name, a->name);

	SHA256((u8 *)header, sizeof(*header) - 32, header->inner_hash);
	return header;
}
	
int write_aspect_header_sector(aspect_t *a)
{
	u8 hash[32];
	u8 bunny_seed[BUNNY_ENTRY_BYTES];
	u8 bunny_output[BUNNY_ENTRY_BYTES];
	steg_cipher_ctx ctx;
	int e, i;
	aspect_disk_header_t *header;
	void *ciphertext = steg_malloc(a->atom_bytes);
	header = setup_disk_header(a);
	/* Calculate bunny pair && encrypt header */
	verbose_printf("\tCalculating header key (level %i)...\n", a->bunny_level);
	bunny_calculate(a->passphrase_hash, a->bunny_level, bunny_seed, bunny_output);
	SHA256(bunny_output, BUNNY_ENTRY_BYTES, hash);
	steg_cipher_init(&ctx, hash, ENCRYPT);
	steg_cipher(&ctx, ciphertext + BUNNY_ENTRY_BYTES, (void *)header, sizeof(*header));
	/* Prepend (bunny seed ^ ciphertext hash) */
	SHA256(ciphertext + BUNNY_ENTRY_BYTES, sizeof(*header), hash);
	for(i = 0; i < 32; i++) {
		bunny_seed[i] ^= hash[i];
	}
	memcpy(ciphertext, bunny_seed, BUNNY_ENTRY_BYTES);
	/* Pad with urandom (if atom > 512 B) and write finished product to disk */
	urandomise(ciphertext + SECTOR_BYTES, a->atom_bytes - SECTOR_BYTES);
	e = write_sectors(a->substrate, get_offset(a, a->header_block), a->atom_bytes, ciphertext);
	steg_cipher_ctx_cleanup(&ctx);
	steg_free(header);
	steg_free(ciphertext);
	return e;
}

void get_data_atom_key(aspect_t *a, u64 offset, u8 *key)
{
	u8 two_parts[KEY_BYTES * 2];
	memcpy(two_parts, &a->block[offset / a->block_bytes], KEY_BYTES);
	memcpy(&two_parts[KEY_BYTES], get_keyfrag_for_offset(a, offset), KEY_BYTES);
	SHA256(two_parts, KEY_BYTES * 2, key);
}

/* Salts hash of plaintext so its on-disk presence is disguised */
void calculate_metadata_hash(aspect_t *a, void *plaintext, u64 *rnd64, block_t *block, keyfrag_t *keyfrag, void *dst)
{
	SHA512_CTX ctx;
	u8 tmp[128];
	u8 hash[64];
	SHA512_Init(&ctx);
	SHA512_Update(&ctx, plaintext, a->meta_atom_bytes);
	memcpy(tmp, a->salt, 56);
	*(u64 *)&tmp[56] = *rnd64;
	memcpy(tmp + 64, block, sizeof(block_t));
	memcpy(tmp + 96, keyfrag, sizeof(keyfrag_t));
	SHA512_Update(&ctx, tmp, 128);
	SHA512_Final(hash, &ctx);
	memcpy(dst, hash, META_HASH_BYTES);
}

void calculate_metadata_key(aspect_t *a, block_t *block, keyfrag_t *keyfrag, void *hash, void *key)
{
	u8 tmp[64];
	SHA256_CTX ctx;
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, hash, META_HASH_BYTES);
	memcpy(tmp, block, KEY_BYTES);
	memcpy(tmp + KEY_BYTES, keyfrag, KEY_BYTES);
	SHA256_Update(&ctx, tmp, KEY_BYTES * 2);
	SHA256_Final(key, &ctx);
}

int encrypt_and_write_meta_atom(aspect_t *a, block_t *index, u64 offset, void *plaintext)
{
	u8 key[KEY_BYTES];
	steg_cipher_ctx ctx;
	u8 hash[META_HASH_BYTES];
	int e;
	u64 rnd64;
	void *ciphertext = steg_malloc(a->atom_bytes);
	block_t *b = &index[offset / a->block_bytes];
	keyfrag_t *keyfrag = get_keyfrag_for_offset(a, offset);
	urandomise(&rnd64, sizeof(u64));
	calculate_metadata_hash(a, plaintext, &rnd64, b, keyfrag, hash);
	calculate_metadata_key(a, b, keyfrag, hash, key);

	steg_cipher_init(&ctx, key, ENCRYPT);
	steg_cipher(&ctx, ciphertext, plaintext, a->meta_atom_bytes);
	steg_cipher_ctx_cleanup(&ctx);

	memcpy(ciphertext + a->meta_atom_bytes, hash, META_HASH_BYTES);
	*(u64 *)(ciphertext + a->meta_atom_bytes + META_HASH_BYTES) = rnd64;
	e = write_sectors(a->substrate, get_offset(a, b) + offset % a->block_bytes, a->atom_bytes, ciphertext);
	steg_free(ciphertext);
	return e;
}

int write_aspect_journal_atom(aspect_t *a)
{
	return encrypt_and_write_meta_atom(a, a->header_block, a->journal_offset, a->journal);
}

/* This is easy because in-memory metadata is padded to multiple of meta_atom_bytes with urandom */
int write_metadata_to_aspect(aspect_t *a, block_t *index, u64 start, u64 total, void *data)
{
	int e;
	total = round_up(total, a->meta_atom_bytes);
	while(total) {
		e = encrypt_and_write_meta_atom(a, index, start, data);
		if(e) {
			return e;
		}
		data += a->meta_atom_bytes;
		start += a->atom_bytes;
		total -= a->meta_atom_bytes;
	}
	return 0;
}

int write_aspect_keyfrags(aspect_t *a)
{
	return write_metadata_to_aspect(a, a->header_block, a->keyfrags_offset, a->atoms_per_block * sizeof(keyfrag_t), a->atom_keyfrag);
}

int write_aspect_index_table(aspect_t *a)
{
	return write_metadata_to_aspect(a, a->header_block, a->index_offset, a->blocks * sizeof(block_t), a->block);
}

/* Decrypts meta atom and checks hash */
int read_and_decrypt_meta_atom(aspect_t *a, block_t *index, u64 offset, void *plaintext)
{
	u8 key[KEY_BYTES];
	steg_cipher_ctx ctx;
	u8 hash[META_HASH_BYTES];
	int e = 0;
	void *ciphertext = steg_malloc(a->atom_bytes);
	block_t *b = &index[offset / a->block_bytes];
	keyfrag_t *keyfrag = get_keyfrag_for_offset(a, offset);
	e = read_sectors(a->substrate, get_offset(a, b) + offset % a->block_bytes, a->atom_bytes, ciphertext);
	if(e) {
		goto end;
	}
	calculate_metadata_key(a, b, keyfrag, ciphertext + a->meta_atom_bytes, key);

	steg_cipher_init(&ctx, key, DECRYPT);
	steg_cipher(&ctx, plaintext, ciphertext, a->meta_atom_bytes);
	steg_cipher_ctx_cleanup(&ctx);

	calculate_metadata_hash(a, plaintext, ciphertext + a->meta_atom_bytes + META_HASH_BYTES, b, keyfrag, hash);
	if(memcmp(ciphertext + a->meta_atom_bytes, hash, META_HASH_BYTES)) {
		e = -EIO;
	}
	end:
	steg_free(ciphertext);
	steg_cipher_ctx_cleanup(&ctx);
	return e;
}

/* Load rest of keyfrags, starting at atom decrypted by keyfrag given in header */
/* read_and_decrypt_meta_atom overwrites data as it uses it - this is ok */
int load_aspect_keyfrags(aspect_t *a)
{
	int e;
	u64 src;
	void *dst;
	/* Load backwards from atom where keyfrag in header was originally stored */
	src = get_offset_of_keyfrag(a, get_seed_keyfrag(a)) & ~(a->atom_bytes - 1);
	dst = &a->atom_keyfrag[(a->meta_atom_bytes * (src - a->keyfrags_offset) / a->atom_bytes) / KEY_BYTES];
	while(src >= a->keyfrags_offset) {
		if((e = read_and_decrypt_meta_atom(a, a->header_block, src, dst))) {
			goto end;
		}
		src -= a->atom_bytes;
		dst -= a->meta_atom_bytes;
	}
	/* And forwards */
	src = get_offset_of_keyfrag(a, get_seed_keyfrag(a)) & ~(a->atom_bytes - 1);
	dst = &a->atom_keyfrag[(a->meta_atom_bytes * (src - a->keyfrags_offset) / a->atom_bytes) / KEY_BYTES];
	while(dst < (void *)get_keyfrag_for_offset(a, a->block_bytes - a->atom_bytes)) {
		if((e = read_and_decrypt_meta_atom(a, a->header_block, src, dst))) {
			goto end;
		}
		src += a->atom_bytes;
		dst += a->meta_atom_bytes;
	}
	end:
	return e;
}

/* Warning: reads in multiples of a->meta_atom_bytes; make sure total is round number */
int read_metadata_from_aspect(aspect_t *a, block_t *index, u64 start, u64 total, void *data)
{
	int e;
	while(total) {
		e = read_and_decrypt_meta_atom(a, index, start, data);
		if(e) {
			return e;
		}
		data += a->meta_atom_bytes;
		start += a->atom_bytes;
		total -= a->meta_atom_bytes;
	}
	return 0;
}

int load_aspect_index_table(aspect_t *a)
{
	int e, i;
	u64 index_table_bytes = round_up(a->blocks * sizeof(block_t), a->meta_atom_bytes);
	a->block = steg_malloc(index_table_bytes);
	if((e = read_metadata_from_aspect(a, a->header_block, a->index_offset, index_table_bytes, a->block))) {
		return e;
	}
	for(i = 0; i < a->blocks; i++) {
		if(get_offset(a, &a->block[i]) + a->block_bytes > a->substrate->bytes) {
			printf("\tError: block beyond end of substrate\n");
			e = -EOVERFLOW;
			break;
		}
	}
	return e;
}

static int get_layer_from_offset(u64 offset)
{
	if(!offset) {
		return 0;
	} else {
		return 65-ffs64(offset);
	}
}

int load_aspect_journal(aspect_t *a)
{
	int e, i;
	u64 offset;
	aspect_disk_journal_t *j;
	j = a->journal = steg_malloc(a->meta_atom_bytes);
	e = read_and_decrypt_meta_atom(a, a->header_block, a->journal_offset, j);
	if(e) {
		steg_free(j);
		return e;
	}
	/* Header block moves are not journalled; j->block_being_moved is always a data block */
	if(j->block_being_moved) {
		offset = get_offset(a, &a->block[pyramid_blocknum(le64toh(j->block_being_moved))]);
		verbose_printf("\tBlock being moved: %zx offset: %zx\n", le64toh(j->block_being_moved), offset);
		verbose_printf("\tSrc_offset %zx dst_offset %zx\n", le64toh(j->src_offset), le64toh(j->dst_offset));
		if(offset == le64toh(j->src_offset)) {
			if(get_layer_from_offset(le64toh(j->src_offset)) > get_layer_from_offset(le64toh(j->dst_offset))) {
				/* Move was a promotion */
				for(i = 0; j->promoted[i] && i < MAX_LAYERS; i++) {
					if(j->promoted[i] == j->block_being_moved) {
						j->promoted[i] = 0;
						if(j->promoted[i + 1]) {
							printf("\tError: journal->promoted[i + 1] != 0\n");
							goto fail;
						}
						break;
					}
				}
				if(i == MAX_LAYERS) {
					printf("\tError: journal->promoted not 0-terminated\n");
					goto fail;
				}
			}
			if(get_layer_from_offset(le64toh(j->src_offset)) < get_layer_from_offset(le64toh(j->dst_offset))) {
				/* Move was a depromotion */
				for(i = 0; j->promoted[i] && i < MAX_LAYERS; i++) { }
				if(i == MAX_LAYERS) {
					printf("\tError: journal->promoted not 0-terminated\n");
					goto fail;
				}
				j->promoted[i] = j->block_being_moved;
				j->promoted[i + 1] = 0;
			}
			j->src_offset = htole64(-1);
			j->block_being_moved = 0;
			/* Probably safest to trigger inter-layer shuffle immediately */
			j->shuffles_left = 0;
			verbose_printf("\tShuffle had not completed. Journal rolled back.\n");
			return -EUCLEAN;
		}
		if(offset == le64toh(j->dst_offset)) {
			j->block_being_moved = 0;
			j->dst_offset = j->src_offset;
			j->src_offset = -1;
			verbose_printf("\tShuffle had completed successfully. Journal updated.\n");
			return -EUCLEAN;
		}
		printf("\tJournal unrecoverable.\n");
		goto fail;
	} else {
		verbose_printf("\tJournal is clean.\n");
	}
	return 0;
	fail:
	steg_free(j);
	return -EINVAL;
}

/* All straight copying, with a bit of calculation */
int load_header(aspect_t *a, aspect_disk_header_t *header, int level, u64 offset)
{
	a->bunny_level = level;
	a->version = le64toh(header->version);
	a->sequence = le64toh(header->sequence);
	a->blocks = le64toh(header->blocks);
	a->block_bytes = le64toh(header->block_bytes);
	a->atom_bytes = le64toh(header->atom_bytes);
	a->encryption = le64toh(header->encryption);
	if(a->encryption > 1) {
		printf("\tWarning: encryption > 1\n");
	}
	a->shuffling = le64toh(header->shuffling);
	if(a->shuffling > 1) {
		printf("\tWarning: shuffling > 1\n");
	}
	a->journalling = le64toh(header->journalling);
	if(a->journalling > 1) {
		printf("\tWarning: journalling > 1\n");
	}
	a->journal_offset = le64toh(header->journal_offset);
	a->keyfrags_offset = le64toh(header->keyfrags_offset);
	a->index_offset = le64toh(header->index_offset);
	a->parent_level = le64toh(header->parent_level);
	memcpy(a->parent_passphrase_hash, header->parent_passphrase_hash, KEY_BYTES);
	a->header_block = &a->header_block_data;
	memcpy(&a->header_block_data, &header->header_block_data, KEY_BYTES);
	a->atoms_per_block = a->block_bytes / a->atom_bytes;
	a->meta_atom_bytes = a->atom_bytes - sizeof(meta_tail_t);
	a->block_t_per_meta_atom = a->meta_atom_bytes / sizeof(block_t);
	a->offset_mask = ~(a->block_bytes - 1);
	a->bytes = a->blocks * a->block_bytes;
	a->atom_keyfrag = steg_realloc(a->atom_keyfrag, round_up(a->atoms_per_block * sizeof(keyfrag_t), a->meta_atom_bytes));
	memcpy(&a->atom_keyfrag[get_seed_keyfrag(a)], &header->seed_keyfrag, KEY_BYTES);
	memcpy(a->salt, header->salt, SALT_BYTES);
	memset(a->name, 0, ASPECT_NAME_BYTES);
	strncpy(a->name, header->name, ASPECT_NAME_BYTES-1);
	return 0;
}

/* Returns a filled out aspect_t * if successful. Also returns an incomplete a->atom_keyfrag */
aspect_t *load_aspect_header_sector(substrate_t *substrate, u8 *passphrase_hash, int min_level, int max_level, int max_tries)
{
	u64 tries, offset, lsb, preferred_offset, lsb_limit = 0;
	u8 hash[32];
	u8 header_key[32];
	u8 bunny_seed[BUNNY_ENTRY_BYTES];
	u8 bunny_output[BUNNY_ENTRY_BYTES];
	steg_cipher_ctx ctx;
	void **bunny_table;
	int i, level, headers_found = 0;
	void *ciphertext = steg_malloc(MINIMUM_ATOM_BYTES);
	aspect_disk_header_t *header = steg_malloc(sizeof(*header));
	aspect_t *a = steg_calloc(1, sizeof(aspect_t));
	a->substrate = substrate;
	/* Precalculate bunny LUTs */
	memcpy(a->passphrase_hash, passphrase_hash, KEY_BYTES);
	bunny_table = steg_calloc(max_level + 1, sizeof(void *));
	for(level = min_level; level <= max_level; level++) {
		verbose_printf("\tPrecalculating level %i...\n", level);
		bunny_table[level] = bunny_precalculate(a->passphrase_hash, level);
	}
	/* Scan up to max_tries addresses in substrate, most aligned first */
	verbose_printf("\tScanning for aspect header...\n");
	if(!max_tries) {
		max_tries = a->substrate->bytes / MINIMUM_BLOCK_BYTES;
	}
	a->sequence = -1;
	for(lsb = (u64)1<<63; lsb > a->substrate->bytes - MINIMUM_BLOCK_BYTES; lsb >>= 1) { }
	for(offset = tries = 0; tries < max_tries; tries++) {
		/* Read potential header sector, attempt decryption at every bunny level */
		read_sector(a->substrate, offset, ciphertext);
		for(level = min_level; level <= max_level; level++) {
			/* Calculate header key */
			memcpy(bunny_seed, ciphertext, BUNNY_ENTRY_BYTES);
			SHA256(ciphertext + BUNNY_ENTRY_BYTES, sizeof(*header), hash);
			for(i = 0; i < 32; i++) {
				bunny_seed[i] ^= hash[i];
			}
			memcpy(bunny_output, bunny_seed, BUNNY_ENTRY_BYTES);
			bunny_hopping(bunny_table[level], bunny_output, level, FALSE);
			SHA256(bunny_output, BUNNY_ENTRY_BYTES, header_key);
			/* Decrypt && check hash */
			steg_cipher_init(&ctx, header_key, DECRYPT);
			steg_cipher(&ctx, (void *)header, ciphertext + BUNNY_ENTRY_BYTES, sizeof(*header));
			SHA256((u8 *)header, sizeof(*header) - 32, hash);
			if(memcmp(hash, header->inner_hash, 32)) {
				goto next;
			}
			if(le64toh(header->version) != ASPECT_HEADER_VERSION) {
				printf("\tIgnoring header found at 0x%zx : wrong version\n", offset);
				goto next;
			}
			verbose_printf("\tValid header found at 0x%zx\n", offset);
			/* We may find two headers. Rock-paper-scissors decides priority */
			if(!((le64toh(header->sequence) + 1) % 3 == a->sequence)) {
				preferred_offset = offset;
				a->header_offset = offset;
				memcpy(a->header_key, header_key, KEY_BYTES);
				load_header(a, header, level, offset);
				memcpy(a->bunny_seed, bunny_seed, BUNNY_ENTRY_BYTES);	/* stegsetup gives this to stegd */
				if(headers_found++) {
					goto found;
				}
				max_tries *= 2;		/* Try hard to find a second header, but not so hard we lock indefinitely */
				lsb_limit = lsb >> 2;	/* Second header can be no lower than 1 pyramid level below first header */
			}
			next:;
		}
		offset += offset ? lsb << 1 : lsb;
		if(offset > substrate->bytes - MINIMUM_BLOCK_BYTES) {
			lsb >>= 1;
			offset = lsb;
			if(lsb == lsb_limit) {
				goto found;
			}
		}
	}
	printf("\tUnable to find header after trying %zu locations\n", tries);
	goto end;
	found:
	verbose_printf("\tUsing header at 0x%zx\n", preferred_offset);
	end:
	for(level = min_level; level <= max_level; level++) {
		steg_free(bunny_table[level]);
	}
	steg_free(bunny_table);
	steg_free(header);
	steg_free(ciphertext);
	steg_cipher_ctx_cleanup(&ctx);
	if(!a->version) {
		steg_free(a->atom_keyfrag);
		steg_free(a);
		return NULL;
	} else {
		return a;
	}
}

/* Recursive loading, for aspects within transparent aspects */
/* Returns NULL-terminated list of pointers to aspect_t's, outermost first */
aspect_t **load_aspects_headers(substrate_t *substrate, u8 *passphrase_hash, int min_level, int max_level, int max_tries)
{
	int i, k;
	aspect_t **ra = NULL, **a;
	/* Find chain of headers */
	for(i = 0; min_level != NO_PARENT; i++) {
		printf("\tSearching for aspect");
		for(k = 0; k < i; k++) {
			printf("'s parent");
		}
		printf("...\n");
		ra = steg_realloc(ra, sizeof(aspect_t *) * (i + 1));
		ra[i] = steg_calloc(1, sizeof(aspect_t));
		ra[i] = load_aspect_header_sector(substrate, passphrase_hash, min_level, max_level, max_tries);
		if(!ra[i]) {
			while(i--) {
				steg_free(ra[i]);
			}
			steg_free(ra);
			return NULL;
		}
		min_level = ra[i]->parent_level;
		max_level = ra[i]->parent_level;
		passphrase_hash = ra[i]->parent_passphrase_hash;
	}
	/* Reverse order */
	a = steg_calloc(i + 2, sizeof(aspect_t *));
	for(k = 0; i--; k++) {
		a[k] = ra[i];
	}
	a[k] = NULL;
	steg_free(ra);
	return a;
}
