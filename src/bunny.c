/* bunny.c - header key generator && crypto stuff */
#include <stdlib.h>
#include <termios.h>
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include "steg.h"

const EVP_CIPHER *EVP_xts;

/* Emulates 'sxts' using xts */
/* Magic ivec encrypts to 0 with key = 0, allowing xts to act as plain aes-128
 * Plain aes-128 is then used with key = 0 to decrypt 2nd half of user key
 * The result is an ivec, which when used with key2 = 0 gives an initial tweak
 * value of user.key2. ie. key1 = key1, T0 = key2. This is sxts.
 * Yes, it's slow, but better than requiring a modified openssl */
void steg_cipher_init(steg_cipher_ctx *ctx, u8 *user_key, int encrypting)
{
	u8 key[32] = { 0 };
	u8 ivec[16] = { 0x14, 0x0f, 0x0f, 0x10, 0x11, 0xb5, 0x22, 0x3d, 0x79, 0x58, 0x77, 0x17, 0xff, 0xd9, 0xec, 0x3a };
	EVP_CipherInit(ctx, EVP_xts, key, ivec, DECRYPT);
	EVP_Cipher(ctx, ivec, user_key + 16, 16);
	memcpy(key, user_key, 16);
	memset(key + 16, 0, 16);
	EVP_CipherInit(ctx, EVP_xts, key, ivec, encrypting);
}

/* T0 = SHA-256(salt || passphrase)
 * Tn = SHA-256(Tn-1 || passphrase)
 * Final hash = T8192 */
void steg_hash_passphrase(u8 *hash, char *passphrase)
{	
	int i, j;
	u8 tmp[64] = { PASSPHRASE_SALT };
	SHA256((u8 *)passphrase, strlen(passphrase), tmp + 32);
	for(i = 0; i < 8192; i++) {
		SHA256(tmp, 64, hash);
		for(j = 0; j < 4; j++) {
			((u64 *)tmp)[j] = ((u64 *)hash)[j];
		}
	}
}

#define PASSPHRASE_BYTES 256
int get_key_hash(u8 *hash)
{
	struct termios old, new;
	char passphrase[PASSPHRASE_BYTES];
	if(tcgetattr(fileno(stdin), &old)) {
		return -1;
	}
	new = old;
	new.c_lflag &= ~ECHO;
	new.c_lflag |= ECHONL | ICANON;
	printf("passphrase: ");
	if(tcsetattr(fileno(stdin), TCSAFLUSH, &new)) {
		return -1;
	}
	if(!fgets(passphrase, PASSPHRASE_BYTES, stdin)) {
		return -1;
	}
	passphrase[strlen(passphrase) - 1] = 0;	/* s/LF// */
	tcsetattr(fileno(stdin), TCSAFLUSH, &old);
	steg_hash_passphrase(hash, passphrase);
	return 0;
}

/* for each hop:
 *	1. state ^= entry 
 *	2. if generating, entry ^= state
 *	3. hash(state, hop number) -> next entry */
void bunny_hopping(void *box, void *_state, int level, int generating)
{
	int hop, i;
	int max_hops = generating ? LEVEL0_GENERATE_HOPS << level : LEVEL0_CALCULATE_HOPS << (level * 2);
	int bits = generating ? LEVEL0_BITS + level : LEVEL0_BITS + (level * 2);
	u64 crc64, *state = _state, *target = box;	/* Start at first entry */
	for(hop = 1; hop < max_hops + 1; hop++) {
		crc64 = 1;
		for(i = 0; i < U64S_PER_ENTRY; i++) {
			state[i] ^= target[i];
			if(generating) {
				target[i] ^= state[i];
			}
			crc64 *= state[i];
		}
		crc64 *= hop;
		target = box + ((crc64 >> (64 - bits)) * BUNNY_ENTRY_BYTES);
	}
}

void bunny_prandomise(void *box, u8 *passphrase_hash, u64 box_bytes, int box_num)
{
#define SUBBOX_CHUNK_BYTES 4096
	steg_cipher_ctx ctx;
	u64 offset;
	u32 key[KEY_BYTES / sizeof(u32)];
	void *tmp = steg_calloc(1, SUBBOX_CHUNK_BYTES);
	for(offset = 0; offset < box_bytes; offset += SUBBOX_CHUNK_BYTES) {
		memcpy(key, passphrase_hash, KEY_BYTES);
		key[0] ^= htole32(box_bytes & 0xffffffff);
		key[1] ^= htole32(box_bytes >> 32);
		key[2] ^= htole32(box_num);
		key[3] ^= htole32(offset / SUBBOX_CHUNK_BYTES);
		key[4] ^= htole32(box_bytes & 0xffffffff);
		key[5] ^= htole32(box_bytes >> 32);
		key[6] ^= htole32(box_num);
		key[7] ^= htole32(offset / SUBBOX_CHUNK_BYTES);
		steg_cipher_init(&ctx, (u8 *)key, ENCRYPT);
		steg_cipher(&ctx, box + offset, tmp, SUBBOX_CHUNK_BYTES);
	}
	steg_cipher_ctx_cleanup(&ctx);
}

/* For each sub-box:
 * 	1. fill with pseudorandom data
 * 	2. let the bunny mix it further */
void generate_subbox(void *subbox, int subbox_num, int level, u8 *passphrase_hash)
{
	u64 bunny_state[U64S_PER_ENTRY];
	bunny_prandomise(subbox, passphrase_hash, (LEVEL0_TOTAL_BYTES << level), subbox_num);
	memset(bunny_state, 0, BUNNY_ENTRY_BYTES);
	bunny_hopping(subbox, bunny_state, level, TRUE);
}

/* For each increment of level:
 *	Twice as many sub-boxes, each one twice as big
 *	Twice as many bunnies (one per sub-box), each doing twice as many hops
 *	Each level should be 4x as time consuming as the last */
void *bunny_precalculate(u8 *passphrase_hash, int level)
{
	int subbox_num;
	void *box = steg_malloc(LEVEL0_TOTAL_BYTES << level * 2);
	for(subbox_num = 0; subbox_num < (1 << level); subbox_num++) {
		generate_subbox(box + (subbox_num * (LEVEL0_TOTAL_BYTES << level)), subbox_num, level, passphrase_hash);
	}
	return box;
}

/* Generates tables, calculates seed/output pair, frees tables */
int bunny_calculate(u8 *passphrase_hash, int level, u8 *seed, u8 *output)
{
	void *data = bunny_precalculate(passphrase_hash, level);
	urandomise(seed, BUNNY_ENTRY_BYTES);
	memcpy(output, seed, BUNNY_ENTRY_BYTES);
	bunny_hopping(data, output, level, FALSE);
	steg_free(data);
	return 0;
}
