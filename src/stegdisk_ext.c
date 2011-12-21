/* stegdisk_ext.c - extent and bitmap functions */
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <openssl/evp.h>
#include <errno.h>
#include "steg.h"
#include "stegdisk.h"

extent_t *ext_alloc(void)
{
	return steg_malloc(sizeof(extent_t));
}

void ext_free(extent_t *e)
{
	steg_free(e);
}

void free_region(extent_t *e)
{
	while(e->next) {
		e = e->next;
		ext_free(e->prev);
	}
	ext_free(e);
}

extent_t *ext_new(extent_t *next, extent_t *prev, u64 base, u64 len)
{
	extent_t *e = ext_alloc();
	e->next = next;
	e->prev = prev;
	e->base = base;
	e->len = len;
	return e;
}

extent_t *ext_new_head(void)
{
	return ext_new(NULL, NULL, 0, 0);
}

extent_t *ext_unlink(extent_t *e)
{
	extent_t *next = e->next;
	e->prev->next = next;
	if(next) {
		next->prev = e->prev;
	}
	ext_free(e);
	return next;
}

extent_t *ext_insert_after(extent_t *e, u64 base, u64 len)
{
	e->next = ext_new(e->next, e, base, len);
	if(e->next->next) {
		e->next->next->prev = e->next;
	}
	return e->next;
}

/* Splits region, returning second part */
extent_t *ext_split(extent_t *e, u64 offset)
{
	while(e->base + e->len <= offset) {
		if(!(e = e->next)) {
			return NULL;
		}
	}
	if(e->base < offset) {
		e = ext_insert_after(e, offset, e->base + e->len - offset);
		e->prev->len = offset - e->prev->base;
	}
	e->prev->next = NULL;
	e->prev = NULL;
	return e;
}

/* Does region contain range? */
int ext_contains_range(extent_t *e, u64 offset, u64 length)
{
	do {
		if(offset >= e->base && offset + length <= e->base + e->len) {
			return 1;
		}
	} while((e = e->next));
	return 0;
}

/* Remove range from region, starting at given extent. */
/* Returns pointer to extent immediately after range */
extent_t *ext_subtract(extent_t *e, u64 offset, u64 bytes)
{
	u64 e_end, b_end;
	while(bytes) {
		while(offset >= e->base + e->len) {
			if(!(e = e->next)) {
				return NULL;
			}
		}
		if(offset < e->base) {
			if(offset + bytes < e->base) {
				return e;
			}
			bytes -= e->base - offset;
			offset = e->base;
		}
		if(e->base == offset) {
			if(e->len > bytes) {
				e->base += bytes;
				e->len -= bytes;
				return e;
			} else {
				bytes -= e->len;
				offset += e->len;
				e = ext_unlink(e);
			}
		} else { /* offset > e->base */
			e_end = e->base + e->len;
			b_end = offset + bytes;
			if(e_end > b_end) {
				ext_insert_after(e, offset + bytes, e_end - b_end);
				e->len = offset - e->base;
				e = e->next;
				bytes = 0;
			}
			if(e_end == b_end) {
				e->len -= bytes;
				bytes = 0;
				e = e->next;
			}
			if(e_end < b_end) {
				bytes -= e_end - offset;
				e->len = offset - e->base;
				offset = b_end;
				e = e->next;
			}
		}
	}
	return e;
}

extent_t *ext_subtract_regions(extent_t *a, extent_t *b)
{
	while(a && b) {
		a = ext_subtract(a, b->base, b->len);
		b = b->next;
	}
	return a;
}

/* Adds range to region, keeping extents in order */
extent_t *ext_add(extent_t *e, u64 offset, u64 bytes)
{
	/* FIXME should merge mergeable extents */
	u64 next_base;
	for(;;) {
		if(e->next) {
			next_base = e->next->base;
		} else {
			next_base = -1;
		}
		if(offset >= e->base && offset < next_base) {
			if(e->base + e->len == offset && e->len) {	/* ie. do not merge head */
				e->len += bytes;
			} else {
				e = ext_insert_after(e, offset, bytes);
			}
			return e;
		} else {
			e = e->next;
		}
	}
}

void ext_add_regions(extent_t *a, extent_t *b)
{
	ext_subtract_regions(a, b);
	b = b->next;
	while(b) {
		a = ext_add(a, b->base, b->len);
		b = b->next;
	}
}

int bitmap_test(u64 *bitmap, u64 bit)
{
	return (bitmap[bit >> 6] >> (bit & 0x3f)) & 1;
}

/* Subtract bitmap of blocks from region */
void ext_subtract_bitmap(extent_t *ext, u64 *bitmap, u64 bits, u64 block_bytes)
{
	int bit;
	extent_t *e = ext;
	for(bit = 0; bit < bits; bit++) {
		if(bitmap_test(bitmap, bit)) {
			if(!(e = ext_subtract(e, bit * block_bytes, block_bytes))) {
				break;
			}
		}
	}
}

void ext_add_bitmap(extent_t *e, u64 *bitmap, u64 bits, u64 block_bytes)
{
	u64 bit;
	ext_subtract_bitmap(e, bitmap, bits, block_bytes);
	for(bit = 0; bit < bits; bit++) {
		if(bitmap_test(bitmap, bit)) {
			e = ext_add(e, bit * block_bytes, block_bytes);
		}
	}
}

void bitmap_set(u64 *bitmap, u64 bit)
{
	bitmap[bit >> 6] |= (u64)1 << (bit & 0x3f);
}

/* Mark blocks that may be carved out of region */
void ext_set_bitmap(u64 *bitmap, extent_t *e, u64 block_bytes)
{
	u64 offset = -1, bytes = 0;
	while((e = e->next)) {
		if(offset + bytes != e->base) {
			offset = e->base;
			bytes = 0;
		}
		bytes += e->len;
		while(bytes >= block_bytes) {
			bitmap_set(bitmap, offset / block_bytes);
			offset += block_bytes;
			bytes -= block_bytes;
		}
	}
}

/* Count bits set in bitmap */
u64 bitmap_bits(u64 *bitmap, u64 bits)
{
	int bit, total;
	for(total = bit = 0; bit < bits; bit++) {
		if(bitmap_test(bitmap, bit)) {
			total++;
		}
	}
	return total;
}

/* Create list of blocks from bitmap, most aligned first */
u64 *bitmap_create_blocklist(u64 *bitmap, u64 max_bytes, u64 block_bytes)
{
	u64 offset, lsb;
	u64 blocks = bitmap_bits(bitmap, max_bytes / block_bytes);
	u64 *b, *limit, *list = steg_malloc(blocks * sizeof(block_t));
	b = list;
	limit = list + blocks;
	if(bitmap_test(bitmap, 0)) {
		*b++ = 0;
	}
	for(lsb = (u64)1<<63; lsb > max_bytes - block_bytes; lsb >>=1) { }
	offset = lsb;
	while(b < limit) {
		if(bitmap_test(bitmap, offset / block_bytes)) {
			*b++ = offset;
		}
		offset += lsb << 1;
		if(offset > max_bytes - block_bytes) {
			lsb >>=1;
			offset = lsb;
		}
	}
	return list;
}

void bitmap_clear(void *bitmap, u64 bits)
{
	memset(bitmap, 0, bits / sizeof(u64));
}

void *bitmap_new(u64 bits)
{
	return steg_calloc((bits >> 6) + (bits & 0x3f ? 1 : 0), 8);
}

void bitmap_free(void *bitmap)
{
	steg_free(bitmap);
}

/* Sets bits corresponding to all blocks used by aspect */
void bitmap_populate(void *bitmap, aspect_t *a)
{
	int i;
	bitmap_set(bitmap, le64toh(a->journal->dst_offset) / a->block_bytes);
	bitmap_set(bitmap, get_offset(a, a->header_block) / a->block_bytes);
	for(i = 0; i < a->blocks; i++) {
		bitmap_set(bitmap, get_offset(a, &a->block[i]) / a->block_bytes);
	}
}
