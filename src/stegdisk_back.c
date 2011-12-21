/* stegdisk_back.c - functions for stegdisk */
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <openssl/evp.h>
#include <errno.h>
#include "steg.h"
#include "stegdisk.h"

#define ATOM_ALLOCATED	1
#define ATOM_POSSIBLE	2

/* Empirically derived formula */
u64 steg_default_block_bytes(u64 bytes)
{
	int i;
	for(i = 20; (u64)1 << i < bytes >> 1; i++) { }
	return (u64)1 << (16 + (((i - 20) * 10) / 22));
}

extent_t *add_region(stegdisk_t *sctx, extent_t *ext)
{
	sctx->regions = steg_realloc(sctx->regions, sizeof(extent_t *) * ++sctx->num_regions);
	sctx->regions[sctx->num_regions - 1] = ext_new_head();
	sctx->regions[sctx->num_regions - 1]->next = ext;
	if(ext) {
		ext->prev = sctx->regions[sctx->num_regions - 1];
		return ext;
	}
	return sctx->regions[sctx->num_regions -1];
}

void remove_region(stegdisk_t *sctx, extent_t *ext)
{
	int i;
	for(i = 0;; i++) {
		if(sctx->regions[i] == ext) {
			for(;i + 1 < sctx->num_regions; i++) {
				sctx->regions[i] = sctx->regions[i + 1];
			}
			sctx->regions = steg_realloc(sctx->regions, --sctx->num_regions * sizeof(extent_t *));
			break;
		}
	}
}

void delete_region(stegdisk_t *sctx, int region)
{
	free_region(sctx->regions[region]);
	remove_region(sctx, sctx->regions[region]);
}

void add_aspect_to_ctx(stegdisk_t *sctx, aspect_t *a)
{
	a->substrate = sctx->substrate;
	sctx->aspects = steg_realloc(sctx->aspects, ++sctx->num_aspects * sizeof(aspect_t *));
	sctx->aspects[sctx->num_aspects - 1] = a;
}

void remove_aspect_from_ctx(stegdisk_t *sctx, aspect_t *a)
{
	int i;
	for(i = 0;; i++) {
		if(sctx->aspects[i] == a) {
			for(;i + 1 < sctx->num_aspects; i++) {
				sctx->aspects[i] = sctx->aspects[i + 1];
			}
			sctx->aspects = steg_realloc(sctx->aspects, --sctx->num_aspects * sizeof(aspect_t *));
			break;
		}
	}
}

void free_ctx(stegdisk_t *ctx)
{
	int i;
	if(ctx) {
		steg_free(ctx->substrate);
		for(i = 0; i < ctx->num_regions; i++) {
			free_region(ctx->regions[i]);
		}
		for(i = 0; i < ctx->num_aspects; i++) {
			free_aspect(ctx->aspects[i]);
		}
		steg_free(ctx);
	}
}

void free_aspect(aspect_t *a)
{
	free_ctx(a->ctx);
	steg_free(a->journal);
	steg_free(a->atom_keyfrag);
	steg_free(a->block);
	steg_free(a);
}

int write_aspect(aspect_t *a)
{
	int e;
	void *data = steg_malloc(SECTOR_BYTES);
	verbose_printf("\tWriting keyfrags...\n");
	if((e = write_aspect_keyfrags(a))) {
		goto end;
	}
	verbose_printf("\tWriting index table...\n");
	if((e = write_aspect_index_table(a))) {
		goto end;
	}
	verbose_printf("\tWriting journal...\n");
	if((e = write_aspect_journal_atom(a))) {
		goto end;
	}
	/* Randomise first atom of free block - prevent residual header being loaded */
	verbose_printf("\tNuking free block...\n");
	urandomise(data, SECTOR_BYTES);
	write_sector(a->substrate, a->journal->dst_offset, data);
	fsync(root_ctx->substrate->handle);
	verbose_printf("\tWriting header...\n");
	if((e = write_aspect_header_sector(a))) {
		goto end;
	}
	a->changes = 0;
	end:
	steg_free(data);
	return e;
}

void write_changes(stegdisk_t *ctx, int force)
{
	int i;
	for(i = 0; i < ctx->num_aspects; i++) {
		write_changes(ctx->aspects[i]->ctx, force);
		if(ctx->aspects[i]->changes || force) {
			if(write_aspect(ctx->aspects[i])) {
				printf("\tWriting meta data failed\n");
			} else {
				printf("\tAspect written\n");
			}
		}
	}
}

int unwritten_changes(stegdisk_t *ctx)
{
	int i, r = 0;
	for(i = 0; i < ctx->num_aspects; i++) {
		if(ctx->aspects[i]->changes) {
			printf("\tWarning: aspect %s has unwritten changes.\n", ctx->aspects[i]->name);
		}
		r += ctx->aspects[i]->changes;
		r += unwritten_changes(ctx->aspects[i]->ctx);
	}
	return r;
}

int menu_write(stegdisk_t *sctx, int argc, void **argv)
{
	if(argc) {
		if(write_aspect(sctx->aspects[*(u64 *)argv[0]])) {
			printf("\tWriting meta data failed\n");
		} else {
			printf("\tAspect written\n");
		}
	} else {
		if(!unwritten_changes(root_ctx)) {
			printf("\tNo unwritten changes.\n");
		}
		write_changes(root_ctx, 0);
	}
	steg_free_args(argc, argv);
	return 0;
}

int menu_forcewrite(stegdisk_t *sctx, int argc, void **argv)
{
	write_changes(root_ctx, 1);
	steg_free_args(argc, argv);
	return 0;
}

int import_export(stegdisk_t *sctx, int exporting, int argc, void **argv)
{
	struct timeval start_tv, finish_tv;
	u64 start, finish;
	char *s;
	aspect_t *a = sctx->aspects[*(u64 *)argv[0]];
	gettimeofday(&start_tv, NULL);
	if(!file_import_export(exporting, a, argv[1])) {
		if(!exporting) {
			fsync(root_ctx->substrate->handle);
		}
		gettimeofday(&finish_tv, NULL);
		start = (start_tv.tv_sec * 1000000) + start_tv.tv_usec;
		finish = (finish_tv.tv_sec * 1000000) + finish_tv.tv_usec;
		s = exporting ? "Exported" : "Imported";
		printf("\tImage %s. %zu bytes in %zu seconds (%zu KB/s)\n", s, a->bytes, (finish - start) / 1000000, ((1000000 * a->bytes) / (finish - start))/1024);
	} else {
		s = exporting ? "Export" : "Import";
		printf("\t%s failed\n", s);
	}
	return 0;
}

int menu_import(stegdisk_t *sctx, int argc, void **argv)
{
	int e = import_export(sctx, 0, argc, argv);
	steg_free_args(argc, argv);
	return e;
}

int menu_export(stegdisk_t *sctx, int argc, void **argv)
{
	int e = import_export(sctx, 1, argc, argv);
	steg_free_args(argc, argv);
	return e;
}

int menu_extent(stegdisk_t *sctx, int argc, void **argv)
{
	u64 offset = *(u64 *)argv[0];
	u64 length = *(u64 *)argv[1];
	if(argc == 3) {
		ext_subtract(sctx->regions[*(u64 *)argv[2]], offset, length);
		ext_add(sctx->regions[*(u64 *)argv[2]], offset, length);
	} else {
		add_region(sctx, ext_new(NULL, NULL, offset, length));
		printf("\tCreated region %i\n", sctx->num_regions - 1);
	}
	steg_free_args(argc, argv);
	return 0;
}

int menu_split(stegdisk_t *sctx, int argc, void **argv)
{
	extent_t *ext, *head = sctx->regions[*(u64 *)argv[0]];
	u64 offset = *(u64 *)argv[1];
	if(!offset) {
		return -EINVAL;
	}
	if(offset & 0x1ff) {
		offset &= ~(u64)0x1ff;
		printf("\toffset not a multiple of sector size; rounding down to 0x%zx\n", offset);
	}
	ext = ext_split(head, offset);
	if(!head->next) {
		head->next = ext;
		ext = NULL;
	}
	steg_free_args(argc, argv);
	if(ext) {
		add_region(sctx, ext);
		printf("\tCreated region %i\n", sctx->num_regions - 1);
		return 0;
	}
	printf("\tSplit failed. region is unchanged\n");
	return -EINVAL;
}

/* urandom is too slow/valuable for filling an entire region, so we generate
 * our own pseudorandom data */
u64 erase_region(substrate_t *substrate, extent_t *e)
{
	steg_cipher_ctx ctx;
	u8 key[KEY_BYTES];
	u64 *in, *out;
	u64 bytes, region_bytes, offset;
	int i;

	in = steg_malloc(CHUNK_BYTES);
	out = steg_malloc(CHUNK_BYTES);
	urandomise(in, CHUNK_BYTES);
	for(region_bytes = 0; e; e = e->next) {
		for(offset = 0; offset < e->len; offset += bytes) {
			bytes = CHUNK_BYTES;
			if(bytes > e->len - offset) {
				bytes = e->len - offset;
			}
			urandomise(key, KEY_BYTES);
			steg_cipher_init(&ctx, key, ENCRYPT);
			steg_cipher(&ctx, (u8 *)out, (u8 *)in, bytes);
			for(i = 0; i < bytes / sizeof(u64); i++) {
				in[i] ^= out[i];
			}
			write_sectors(substrate, e->base + offset, bytes, out);
		}
		region_bytes += e->len;
	}
	steg_free(in);
	steg_free(out);
	return region_bytes;
}

int menu_nuke(stegdisk_t *sctx, int argc, void **argv)
{
	u64 addresses, lsb;
	int i, targets;
	u64 offset = 0;
	u64 passes = 1;
	u64 region = *(u64 *)argv[0];
	extent_t *head = ext_new_head();
	if(argc == 2) {
		passes = *(u64 *)argv[1] ? : 1;
	}
	addresses = sctx->default_max_tries;
	if(addresses < DEFAULT_MAX_TRIES) {
		addresses = DEFAULT_MAX_TRIES;
	}
	/* Work out how many of substrate's most aligned addresses are within region */
	for(lsb = (u64)1<<63; lsb > sctx->substrate->bytes - MINIMUM_BLOCK_BYTES; lsb >>= 1) { }
	for(i = targets = 0; i < addresses; i++) {
		if(ext_contains_range(sctx->regions[region], offset, SECTOR_BYTES)) {
			ext_add(head, offset, SECTOR_BYTES);
			targets++;
		}
		offset += offset ? lsb << 1 : lsb;
		if(offset > sctx->substrate->bytes - MINIMUM_BLOCK_BYTES) {
			lsb >>= 1;
			offset = lsb;
		}
	}
	verbose_printf("\tRegion %zu has %i of the substrate's %zu most aligned offsets\n", region, targets, addresses);
	printf("\t%zu-pass nuking the %i most aligned addreses in region %zu...\n", passes, targets, region);
	do {
		erase_region(sctx->substrate, head);
		fsync(root_ctx->substrate->handle);
	} while(--passes);
	free_region(head);
	steg_free_args(argc, argv);
	return 0;
}

int menu_erase(stegdisk_t *sctx, int argc, void **argv)
{
	struct timeval start_tv, finish_tv;
	u64 start, finish;
	u64 region = *(u64 *)argv[0];
	u64 region_bytes;
	printf("\tErasing region %zu...\n", region);
	gettimeofday(&start_tv, NULL);
	region_bytes = erase_region(sctx->substrate, sctx->regions[region]);
	fsync(root_ctx->substrate->handle);
	gettimeofday(&finish_tv, NULL);
	start = (start_tv.tv_sec * 1000000) + start_tv.tv_usec;
	finish = (finish_tv.tv_sec * 1000000) + finish_tv.tv_usec + 1; /* !SIGFPE */
	printf("\n\tDone. %zu bytes in %zu seconds (%zu KB/s)\n", region_bytes, (finish - start) / 1000000, ((1000 * region_bytes) / ((finish - start) / 1000))/1024);
	steg_free_args(argc, argv);
	return 0;
}

stegdisk_t *new_ctx(stegdisk_t *sctx, substrate_t *substrate)
{
	stegdisk_t *ctx = steg_malloc(sizeof(stegdisk_t));
	memcpy(ctx, sctx, sizeof(stegdisk_t));
	ctx->substrate = substrate;
	ctx->regions = NULL;
	ctx->num_regions = 0;
	ctx->aspects = NULL;
	ctx->num_aspects = 0;
	ctx->default_block_bytes = substrate->aspect->block_bytes;
	ctx->default_atom_bytes = substrate->aspect->atom_bytes;
	ctx->default_shuffling = 0;
	add_region(ctx, ext_new(NULL, NULL, 0, substrate->bytes));
	return ctx;
}

substrate_t *new_substrate(aspect_t *a)
{
	substrate_t *s = steg_calloc(1, sizeof(substrate_t));
	s->aspect = a;
	s->filename = steg_malloc(strlen(a->name) + 1);
	strcpy(s->filename, a->name);
	s->bytes = a->bytes;
	return s;
}

void subtract_aspect_from_region(stegdisk_t *sctx, int region, aspect_t *a)
{
	void *bitmap;
	verbose_printf("\tUpdating region %i...\n", region);
	bitmap = bitmap_new(sctx->substrate->bytes / a->block_bytes);
	bitmap_populate(bitmap, a);
	ext_subtract_bitmap(sctx->regions[region], bitmap, sctx->substrate->bytes / a->block_bytes, a->block_bytes);
	bitmap_free(bitmap);
}

aspect_t *aspect_loaded_already(stegdisk_t *ctx, aspect_t *a)
{
	aspect_t *aspect;
	int i;
	for(i = 0; i < ctx->num_aspects; i++) {
		if(!memcmp(ctx->aspects[i]->salt, a->salt, SALT_BYTES)) {
			return ctx->aspects[i];
		}
		if((aspect = aspect_loaded_already(ctx->aspects[i]->ctx, a))) {
			return aspect;
		}
	}
	return NULL;
}

int menu_load(stegdisk_t *sctx, int argc, void **argv)
{
	int i, k, e = -EINVAL;
	aspect_t *aspect, **a;
	stegdisk_t *ctx;
	u64 header_offset;
	/* Get chain of headers */
	a = load_aspects_headers(sctx->substrate, argv[0], 0, sctx->default_max_level, sctx->default_max_tries);
	if(!a) {
		goto end;
	}
	/* Find out how many are loaded already */
	for(i = 0; a[i]; i++) {
		if((aspect = aspect_loaded_already(root_ctx, a[i]))) {
			free_aspect(a[i]);
			a[i] = aspect;
			printf("\tAspect %s already loaded\n", aspect->name);
		} else {
			break;
		}
	}
	/* Load the rest */
	for(; a[i]; i++) {
		/* Reverse-map and check header addresses */
		for(k = 1, header_offset = a[i]->header_offset; k <= i; k++) {
			header_offset = get_offset_reverse(a[k - 1], header_offset);
		}
		a[i]->substrate = i ? a[i - 1]->ctx->substrate : sctx->substrate;
		if(header_offset != get_offset(a[i], a[i]->header_block)) {
			printf("\tHeader confused about its offset. refusing to mount");
			goto fail;
		}
		/* Load rest of aspect meta data */
		verbose_printf("\tLoading keyfrags...\n");
		if(load_aspect_keyfrags(a[i])) {
			printf("\tLoading keyfrags failed\n");
			goto fail;
		}
		verbose_printf("\tLoading index table...\n");
		if(load_aspect_index_table(a[i])) {
			printf("\tLoading index table failed\n");
			goto fail;
		}
		verbose_printf("\tLoading journal...\n");
		if((e = load_aspect_journal(a[i]))) {
			if(e == -EUCLEAN) {
				a[i]->changes++;
				printf("\tUse write command to update journal on disk");
			} else {
				printf("\tLoading journal failed\n");
			}
		}
		/* Update context in which this aspect was spawned */
		ctx = i ? a[i - 1]->ctx : sctx;
		printf("\tCreated aspect %i within context %s\n", ctx->num_aspects, ctx->substrate->filename);
		add_aspect_to_ctx(ctx, a[i]);
		subtract_aspect_from_region(ctx, 0, a[i]);
		/* Create new context for within this aspect */
		a[i]->ctx = new_ctx(ctx, new_substrate(a[i]));
	}
	e = 0;
	end:
	steg_free(a);
	steg_free_args(argc, argv);
	return e;
	fail:
	for(i = 0; a[i]; i++) {
		free_aspect(a[i]);
	}
	goto end;
}

u64 get_blocks_from_total(char *arg, u64 available_blocks, u64 block_bytes)
{
	char *c;
	u64 blocks = strtoul(arg, &c, 10);
	if(arg == c) {
		printf("\tBad number/percentage\n");
		return -EINVAL;
	}
	if(*c == '%') {
		if(blocks > 100) {
			printf("\tBad percentage\n");
			return -EINVAL;
		}
		blocks = (available_blocks * blocks) / 100;
		printf("\tUsing %s of available blocks (%zu blocks of %zu KB)\n", arg, blocks, block_bytes / 1024);
	} else {
		if(blocks > available_blocks) {
			printf("\tOnly %zu blocks of %zu bytes available\n", available_blocks, block_bytes);
			return -EINVAL;
		}
	}
	return blocks;
}

/* returns offset within block of suitable length sequence of unallocated atoms */
/* contiguous == number of atoms in row, allocate == number to allocate */
u64 get_contiguous_atoms(aspect_t *a, int *atom, int contiguous, int allocate)
{
	unsigned int rnd;
	int first = 0, last, candidates = 0;
	/* Mark atoms that begin suitable sequences */
	tryagain:
	while(atom[first] == ATOM_ALLOCATED) { first++; }
	last = first;
	while(last < a->atoms_per_block) {
		if(atom[last] == ATOM_ALLOCATED) {
			first = last;
			goto tryagain;
		}
		if(last - first >= contiguous) {
			atom[first] = ATOM_POSSIBLE;
			candidates++;
			first++;
		}
		last++;
	}
	/* Randomly select suitable atom */
	urandomise(&rnd, sizeof(unsigned int));
	rnd %= candidates;
	for(first = candidates = 0;; first++) {
		if(atom[first] == ATOM_POSSIBLE) {
			if(candidates == rnd) {
				break;
			}
			candidates++;
		}
	}
	/* Mark as allocated */
	for(last = first; last - first < allocate; last++) {
		atom[last] |= ATOM_ALLOCATED;
	}
	/* Remove ATOM_POSSIBLE marks */
	for(last = 0; last < a->atoms_per_block; last++) {
		atom[last] &= ATOM_ALLOCATED;
	}
	return first * a->atom_bytes;
}

int menu_passphrase(stegdisk_t *sctx, int argc, void **argv)
{
	memcpy(sctx->aspects[*(u64 *)argv[0]]->passphrase_hash, argv[1], KEY_BYTES);
	sctx->aspects[*(u64 *)argv[0]]->changes++;
	steg_free_args(argc, argv);
	return 0;
}

int menu_unload(stegdisk_t *sctx, int argc, void **argv)
{
	aspect_t *a = sctx->aspects[*(u64 *)argv[0]];
	void *bitmap = bitmap_new(sctx->substrate->bytes / a->block_bytes);
	bitmap_populate(bitmap, a);
	ext_add_bitmap(sctx->regions[0], bitmap, sctx->substrate->bytes / a->block_bytes, a->block_bytes);
	free_aspect(a);
	remove_aspect_from_ctx(sctx, a);
	bitmap_free(bitmap);
	steg_free_args(argc, argv);
	return 0;
}

int menu_remove(stegdisk_t *sctx, int argc, void **argv)
{
	if(!*(u64 *)argv[0]) {
		printf("\tRefusing to remove default region\n");
	} else {
		delete_region(sctx, *(u64 *)argv[0]);
		steg_free_args(argc, argv);
	}
	return 0;
}

int menu_subtract(stegdisk_t *sctx, int argc, void **argv)
{
	ext_subtract_regions(sctx->regions[*(u64 *)argv[0]], sctx->regions[*(u64 *)argv[1]]);
	steg_free_args(argc, argv);
	return 0;
}

int menu_add(stegdisk_t *sctx, int argc, void **argv)
{
	ext_add_regions(sctx->regions[*(u64 *)argv[0]], sctx->regions[*(u64 *)argv[1]]);
	steg_free_args(argc, argv);
	return 0;
}

int menu_steal(stegdisk_t *sctx, int argc, void **argv)
{
	extent_t *ext;
	aspect_t *a = sctx->aspects[*(u64 *)argv[0]];
	void *bitmap = bitmap_new(sctx->substrate->bytes / a->block_bytes);
	u64 total_blocks = get_blocks_from_total(argv[1], a->blocks, a->block_bytes);
	block_t *block;
	if(total_blocks == -EINVAL) {
		goto end;
	}
	ext = add_region(sctx, NULL);
	for(block = &a->block[a->blocks - 1]; total_blocks; block--, total_blocks--) {
		bitmap_set(bitmap, get_offset(a, block) / a->block_bytes);
	}
	ext_add_bitmap(ext, bitmap, sctx->substrate->bytes / a->block_bytes, a->block_bytes);
	printf("\tCreated region %i\n", sctx->num_regions - 1);
	end:
	bitmap_free(bitmap);
	steg_free_args(argc, argv);
	return total_blocks;
}

int menu_metaregion(stegdisk_t *sctx, int argc, void **argv)
{
	aspect_t *a = sctx->aspects[*(u64 *)argv[0]];
	extent_t *ext = add_region(sctx, NULL);
	ext_add(ext, le64toh(a->journal->dst_offset), a->block_bytes);
	ext_add(ext, get_offset(a, a->header_block), a->block_bytes);
	printf("\tCreated region %i\n", sctx->num_regions - 1);
	steg_free_args(argc, argv);
	return 0;
}

/* Padded out to multiple of meta_atom_bytes for disk storage */
block_t *allocate_index_unaligned(aspect_t *a, u64 entries, u64 **unaligned)
{
	u64 bytes = round_up(entries * sizeof(block_t), a->meta_atom_bytes);
	int i;
	block_t *array = steg_malloc(bytes);
	urandomise(array, bytes);
	for(i = 0; i < entries; i++) {
		set_offset(a, &array[i], htole64(*--(*unaligned)));
	}
	return array;
}

/* Assigns more aligned physical addresses to more aligned virtual addresses,
 * so as to preserve alignment hierachy inside a transparent aspect.
 * Conserves aligned addresses by using an amount proportional to the aspect's
 * use of its region. */
block_t *allocate_block_index_aligned(aspect_t *a, u64 *aligned, u64 *unaligned)
{
	u64 lsb, offset = 0, entries = a->blocks;
	u64 bytes = round_up(a->blocks * sizeof(block_t), a->meta_atom_bytes);
	u64 gradient = unaligned - aligned;
	u64 fp = 0;
	block_t *array = steg_malloc(bytes);
	urandomise(array, bytes);
	gradient <<= 32;
	gradient /= entries;
	for(lsb = (u64)1<<63; lsb > (a->blocks - 1) * a->block_bytes; lsb >>=1) { }
	while(entries--) {
		set_offset(a, &array[offset / a->block_bytes], aligned[fp >> 32]);
		fp += gradient;
		offset += offset ? lsb << 1 : lsb;
		if(offset > (a->blocks - 1) * a->block_bytes) {
			lsb >>=1;
			offset = lsb;
		}
	}
	return array;
}

int menu_new(stegdisk_t *sctx, int argc, void **argv)
{
	u8 transparent_hash[KEY_BYTES] = { TRANSPARENT_HASH };
	u64 region = *(u64 *)argv[0];
	u64 *blocklist = NULL;
	aspect_t *a = steg_calloc(1, sizeof(aspect_t));
	int *allocated, transparent = 0, e = -EINVAL;
	void *bitmap = bitmap_new(sctx->substrate->bytes / sctx->default_block_bytes);
	u64 available_blocks, total_blocks, keyfrag_atoms, index_table_atoms;
	u64 *aligned, *unaligned;
	if(!memcmp(argv[3], transparent_hash, KEY_BYTES)) {
		transparent = 1;
	}
	ext_set_bitmap(bitmap, sctx->regions[region], sctx->default_block_bytes);
	available_blocks = bitmap_bits(bitmap, sctx->substrate->bytes / sctx->default_block_bytes);
	if((total_blocks = get_blocks_from_total(argv[1], available_blocks, sctx->default_block_bytes)) == -EINVAL) {
		goto end;
	}
	if(total_blocks < 3) {
		printf("\tTrying to create aspect with %zu blocks. Minimum is 3.\n", total_blocks);
		goto end;
	}
	if(!sctx->num_aspects) {
		printf("\tWarning: Creating new aspect in blank substrate. Existing data may be\n\toverwritten.\n");
		printf("\tWarning: Assuming substrate has been securely erased.\n");
	}
	a->block_bytes = sctx->default_block_bytes;
	a->atom_bytes = sctx->default_atom_bytes;
	a->atoms_per_block = a->block_bytes / a->atom_bytes;
	a->meta_atom_bytes = a->atom_bytes - sizeof(meta_tail_t);
	a->blocks = total_blocks - 2;	/* Free + header */
	keyfrag_atoms = round_up(a->atoms_per_block * sizeof(keyfrag_t), a->meta_atom_bytes) / a->meta_atom_bytes;
	index_table_atoms = round_up(a->blocks * sizeof(block_t), a->meta_atom_bytes) / a->meta_atom_bytes;
	if(2 + keyfrag_atoms + index_table_atoms > a->atoms_per_block) {
		printf("\tBlock size too small for an aspect this large.\n");
		goto end;
	}
	a->sequence = 0;
	a->block_t_per_meta_atom = a->meta_atom_bytes / sizeof(block_t);
	a->bytes = a->blocks * a->block_bytes;
	a->offset_mask = ~(a->block_bytes - 1);
	a->version = ASPECT_HEADER_VERSION;
	a->shuffling = sctx->default_shuffling;
	a->journalling = sctx->default_journalling;
	strncpy(a->name, argv[2], ASPECT_NAME_BYTES - 1);
	if(transparent) {
		a->encryption = 0;
		a->bunny_level = TRANSPARENT_BUNNY_LEVEL;
		urandomise(a->passphrase_hash, KEY_BYTES);
	} else {
		a->encryption = sctx->default_encryption;
		a->bunny_level = sctx->default_bunny_level;
		memcpy(a->passphrase_hash, argv[3], KEY_BYTES);
	}
	if(sctx->substrate->aspect) {
		a->parent_level = sctx->substrate->aspect->bunny_level;
		memcpy(a->parent_passphrase_hash, sctx->substrate->aspect->passphrase_hash, KEY_BYTES);
	} else {
		a->parent_level = NO_PARENT;
	}
	a->header_block = &a->header_block_data;

	/* Randomise layout of header block.
	 * Loop until seed keyfrag not the first or last in it's atom (which
	 * would make loading the rest impossible) */
	verbose_printf("\tRandomising header block layout...\n");
	allocated = steg_malloc(a->atoms_per_block * sizeof(int));
	do {
		memset(allocated, 0, a->atoms_per_block * sizeof(int));
		allocated[0] = ATOM_ALLOCATED;
		a->index_offset = get_contiguous_atoms(a, allocated, index_table_atoms + keyfrag_atoms, index_table_atoms);
		a->keyfrags_offset = get_contiguous_atoms(a, allocated, keyfrag_atoms, keyfrag_atoms);
		a->journal_offset = get_contiguous_atoms(a, allocated, 1, 1);
	} while(!(get_seed_keyfrag(a) % a->block_t_per_meta_atom) || get_seed_keyfrag(a) % a->block_t_per_meta_atom == a->block_t_per_meta_atom - 1);
	steg_free(allocated);

	/* These 2 can have the higher quality urandom data */
	urandomise(a->salt, SALT_BYTES);
	urandomise(a->header_block, KEY_BYTES);

	/* Now the bigger arrays get sloppy seconds */
	verbose_printf("\tRandomising atom keyfrags...\n");
	a->atom_keyfrag = steg_malloc(keyfrag_atoms * a->meta_atom_bytes);
	urandomise(a->atom_keyfrag, keyfrag_atoms * a->meta_atom_bytes);

	/* Set up journal && allocate free block */
	blocklist = bitmap_create_blocklist(bitmap, sctx->substrate->bytes, a->block_bytes);
	aligned = blocklist;
	a->journal = steg_malloc(a->meta_atom_bytes);
	urandomise(a->journal, a->meta_atom_bytes);
	a->journal->block_being_moved = 0;					/* no move in progress */
	a->journal->dst_offset = htole64(*aligned++);				/* free block */
	verbose_printf("\tFree block: %zx\n", le64toh(a->journal->dst_offset));
	a->journal->ascending = 0;						/* initially move down pyramid */
	a->journal->shuffles_left = 0;						/* move down immediately */
	a->journal->promoted[0] = 0;						/* 0-terminated list: ie. no blocks promoted */

	set_offset(a, a->header_block, *aligned++);
	verbose_printf("\tHeader block: %zx\n", get_offset(a, a->header_block));
	verbose_printf("\tSetting up index table...\n");
	unaligned = &blocklist[available_blocks];
	if(transparent) {
		a->block = allocate_block_index_aligned(a, aligned, unaligned);	/* does not update aligned/unaligned */
	} else {
		a->block = allocate_index_unaligned(a, a->blocks, &unaligned);
	}
	printf("\tCreated %s aspect %i\n", transparent ? "transparent" : "encrypted", sctx->num_aspects);
	add_aspect_to_ctx(sctx, a);
	subtract_aspect_from_region(sctx, region, a);
	a->ctx = new_ctx(sctx, new_substrate(a));
	a->changes++;
	e = 0;
	end:
	steg_free(blocklist);
	bitmap_free(bitmap);
	if(e) {
		steg_free(a);
	}
	steg_free_args(argc, argv);
	return e;
}
