/* stegdisk.c - UI for the fdisk-like aspect management utility */
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <errno.h>
#include "steg.h"
#include "stegdisk.h"

stegdisk_t *root_ctx;

/* Argument-aquiring functions for menu command handlers */

void *parse_string(stegdisk_t *sctx, char *s)
{
	char *dup = steg_malloc(strlen(s) + 1);
	strcpy(dup, s);
	return dup;
}

void *prompt_string(char *type)
{
	char buf[BUFLEN];
	void *arg = NULL;
	printf("%s: ", type);
	if(fgets(buf, BUFLEN, stdin)) {
		buf[strlen(buf) - 1] = 0;	/* s/LF// */
		arg = parse_string(NULL, buf);
	}
	return arg;
}

menu_arg_t ma_string = {
			.parse = parse_string,
			.prompt = NULL
};

void *parse_passphrase(stegdisk_t *sctx, char *s)
{
	u8 *hash = steg_malloc(KEY_BYTES);
	steg_hash_passphrase(hash, s);
	return hash;
}

void *prompt_passphrase(stegdisk_t *sctx)
{
	void *hash = steg_malloc(KEY_BYTES);
	if(get_key_hash(hash)) {
		steg_free(hash);
		return NULL;
	}
	return hash;
}

menu_arg_t ma_passphrase = {
			.parse = parse_passphrase,
			.prompt = prompt_passphrase
};

void *parse_number(char *s, char *type, u64 max)
{
	u64 *arg;
	char *c;
	u64 r;
	if(s[0] == 'y' || s[0] == 'Y') {
		arg = steg_malloc(sizeof(u64));
		*arg = 1;
		return arg;
	}
	if(s[0] == 'n' || s[0] == 'N') {
		arg = steg_malloc(sizeof(u64));
		*arg = 0;
		return arg;
	}
	r = strtoull(s, &c, 0);
	if(s != c) {
		r = kmgt_multiply(r, c);
		if(r < max) {
			arg = steg_malloc(sizeof(u64));
			*arg = r;
			return arg;
		}
		if(max) {
			printf("\t%s %lu too high. Maximum %zu\n", type, r, max - 1);
		} else {
			printf("\tNo %ss known.\n", type);
		}
	}
	return NULL;
}

void *parse_region(stegdisk_t *sctx, char *s)
{
	return parse_number(s, "region", sctx->num_regions);
}

void *parse_aspect(stegdisk_t *sctx, char *s)
{
	return parse_number(s, "aspect", sctx->num_aspects);
}

void *prompt_number(char *type, unsigned int max)
{
	void *arg = NULL;
	char buf[BUFLEN];
	printf("%s: ", type);
	if(fgets(buf, BUFLEN, stdin)) {
		buf[strlen(buf) - 1] = 0;	/* s/LF// */
		arg = parse_number(buf, type, max);
	}
	return arg;
}

void *prompt_region(stegdisk_t *sctx)
{
	return prompt_number("region", sctx->num_regions);
}

void *prompt_aspect(stegdisk_t *sctx)
{
	return prompt_number("aspect", sctx->num_aspects);
}

menu_arg_t ma_region = {
			.parse = parse_region,
			.prompt = prompt_region
};

menu_arg_t ma_aspect = {
			.parse = parse_aspect,
			.prompt = prompt_aspect 
};

void *parse_blocks(stegdisk_t *sctx, char *s)
{
	return parse_string(sctx, s);
}

void *prompt_blocks(stegdisk_t *sctx)
{
	return prompt_string("blocks (number, or %%age of region)");
}

menu_arg_t ma_blocks = {
			.parse = parse_blocks,
			.prompt = prompt_blocks
};

void *prompt_filename(stegdisk_t *sctx)
{
	return prompt_string("filename");
}

menu_arg_t ma_filename = {
			.parse = parse_string,
			.prompt = prompt_filename
};

void *prompt_set(stegdisk_t *sctx)
{
	return prompt_string("set");
}

menu_arg_t ma_set = {
			.parse = parse_string,
			.prompt = prompt_set
};

void *parse_value(stegdisk_t *sctx, char *s)
{
	return parse_number(s, "value", -1);
}

void *prompt_value(stegdisk_t *sctx)
{
	return prompt_number("value", -1);
}

menu_arg_t ma_value = {
			.parse = parse_value,
			.prompt = prompt_value
};

void *parse_offset(stegdisk_t *sctx, char *s)
{	
	return parse_number(s, "offset", -1);
}

void *prompt_offset(stegdisk_t *sctx)
{
	return prompt_number("offset", -1);
}

menu_arg_t ma_offset = {
			.parse = parse_offset,
			.prompt = prompt_offset
};

void *parse_length(stegdisk_t *sctx, char *s)
{	
	return parse_number(s, "length", -1);
}

void *prompt_length(stegdisk_t *sctx)
{
	return prompt_number("length", -1);
}

menu_arg_t ma_length = {
			.parse = parse_length,
			.prompt = prompt_length,
};

void *prompt_name(stegdisk_t *sctx)
{
	return prompt_string("name");
}

menu_arg_t ma_name = {
			.parse = parse_string,
			.prompt = prompt_name
};

/* Menu commands */

menu_arg_t *string_argv[] = { &ma_string, NULL };
menu_entry_t m_help = {
			.cmd = "help",
			.help = "display this text",
			.usage = " [command] ",
			.description = NULL,
			.min_argc = 0,
			.argv = string_argv,
			.func = menu_help
};

menu_entry_t m_quit = {
			.cmd = "quit",
			.help = "exit without writing changes",
			.usage = NULL,
			.description = NULL,
			.min_argc = 0,
			.argv = string_argv,
			.func = menu_quit
};

menu_arg_t *aspect_argv[] = { &ma_aspect, &ma_string, &ma_value, NULL };
menu_entry_t m_aspect = {
			.cmd = "aspect",
			.help = "show aspect info or set attribute",
			.usage = " [aspect] [attribute] [value] ",
			.description = "\n\
\tNo args:\tdisplay all aspects\n\
\tOne arg:\tdisplay info for specified aspect\n\
\tFour args:\tset aspect attribute to value\n\n\
\tKey\tAttribute\n\n\
\te\tEncryption enabled\n\
\ts\tShuffling enabled\n\
\tj\tJournalling enabled\n\
\tb\tBunny level for header encryption\n\
\to\tJournal offset\n\
\tk\tKeyfrags offset\n\
\ti\tIndex table offset\n\
\tl\tShuffles left on layer\n",
			.min_argc = 0,
			.argv = aspect_argv,
			.func = menu_aspect
};

menu_arg_t *rename_argv[] = { &ma_aspect, &ma_name, NULL };
menu_entry_t m_rename = {
			.cmd = "rename",
			.help = "rename aspect",
			.usage = " <aspect> <name> ",
			.description = NULL,
			.min_argc = 2,
			.argv = rename_argv,
			.func = menu_rename
};

menu_arg_t *region_argv[] = { &ma_region, NULL };
menu_entry_t m_region = {
			.cmd = "region",
			.help = "print region info",
			.usage = NULL,
			.description = NULL,
			.min_argc = 0,
			.argv = region_argv,
			.func = menu_region
};

menu_arg_t *null_argv[] = { NULL };
menu_entry_t m_print = {
			.cmd = "print",
			.help = "show all regions and aspects",
			.usage = NULL,
			.description = NULL,
			.min_argc = 0,
			.argv = null_argv,
			.func = menu_print
};

menu_arg_t *load_argv[] = { &ma_passphrase, NULL };
menu_entry_t m_load = {
			.cmd = "load",
			.help = "load aspect",
			.usage = " [passphrase] ",
			.description = NULL,
			.min_argc = 1,
			.argv = load_argv,
			.func = menu_load
};

menu_arg_t *erase_argv[] = { &ma_region, NULL };
menu_entry_t m_erase = {
			.cmd = "erase",
			.help = "overwrite region with pseudorandom data",
			.usage = " <region> ",
			.description = "\n\
\tThe use of this function is recommended for initialising block\n\
\tdevices that have previously not been used for steg. The presence\n\
\tof fragments of unencrypted data can give away information about\n\
\tthe aspects in use.\n\
\t\terase uses a urandom/AES based algoritm. It will generate good\n\
\tquality psueodrandom data, but uses only a single pass and may\n\
\tnot prevent forensic recovery of previous disk contents. Use a more\n\
\tspecialised tool if this is a concern.\n",
			.min_argc = 1,
			.argv = erase_argv,
			.func = menu_erase
};

menu_arg_t *unload_argv[] = { &ma_aspect, NULL };
menu_entry_t m_unload = {
			.cmd = "unload",
			.help = "unload aspect",
			.usage = " <aspect> ",
			.description = "\n\
\tRemoves aspect from memory but does not alter aspect's on-disk presence\n\
\tUse the following commands to permanently remove an aspect:\n\
\t\tmetaregion 0\n\
\t\terase <new region>\n",
			.min_argc = 1,
			.argv = unload_argv,
			.func = menu_unload
};

menu_entry_t m_remove = {
			.cmd = "remove",
			.help = "remove region",
			.usage = " <region> ",
			.description = NULL,
			.min_argc = 1,
			.argv = erase_argv,
			.func = menu_remove
};

menu_arg_t *nuke_argv[] = { &ma_region, &ma_value, NULL };
menu_entry_t m_nuke = {
			.cmd = "nuke",
			.help = "overwrites aligned addresses",
			.usage = " <region> [passes] ",
			.description = "\n\
\tWrites pseudorandom data to the most aligned addresses in a region.\n\
\tThis is a quick way of removing all headers, rendering the associated\n\
\taspects' data impossible to read.\n",
			.min_argc = 1,
			.argv = nuke_argv,
			.func = menu_nuke
};

menu_arg_t *extent_argv[] = { &ma_offset, &ma_length, &ma_region, NULL };
menu_entry_t m_extent = {
			.cmd = "extent",
			.help = "create extent",
			.usage = " <offset> <length> [region] ",
			.description = "\n\
\tAdds an extent to a region, or creates a new region with the given\n\
\textent.\n",
			.min_argc = 2,
			.argv = extent_argv,
			.func = menu_extent
};

menu_arg_t *split_argv[] = { &ma_region, &ma_offset, NULL };
menu_entry_t m_split = {
			.cmd = "split",
			.help = "split region at offset",
			.usage = " <region> <offset/%age> ",
			.description = "\n\
\tSplits region into two parts, with a cutoff at the given offset.\n\
\tThere is no effect on the underlying device; regions are purely an\n\
\tabstract concept for allocating space for aspects.\n\
\teg.\n\
\t\tsplit 0 1000000000\n\
\t\tsplit 2 50M\n\
\t\tsplit 5 10G\n",
			.min_argc = 2,
			.argv = split_argv,
			.func = menu_split
};

menu_arg_t *steal_argv[] = { &ma_aspect, &ma_blocks, NULL };
menu_entry_t m_steal = {
			.cmd = "steal",
			.help = "steal blocks from aspect",
			.usage = " <aspect> <blocks> ",
			.description = "\n\
\tCreates a new region by stealing data blocks from the end of an\n\
\taspect. This can be used to create overlapping aspects, a sneaky\n\
\tway of hiding data. eg.\n\
\t\tsteal 1 100\n\
\t\tsteal 0 5%\n\
\tCare must be taken when writing to the first aspect so as not to\n\
\taccidentally overwrite the second aspect.\n",
			.min_argc = 2,
			.argv = steal_argv,
			.func = menu_steal
};

menu_arg_t *metaregion_argv[] = { &ma_aspect, NULL };
menu_entry_t m_metaregion = {
			.cmd = "metaregion",
			.help = "create region from aspect metadata",
			.usage = " <aspect> ",
			.description = "\n\
\tCreates a new region from the free block and header block of\n\
\tthe specified aspect. Can be used to nuke an aspect:\n\
\t\tmetaregion 0\n\
\t\terase <new region>\n",
			.min_argc = 1,
			.argv = metaregion_argv,
			.func = menu_metaregion
};

menu_arg_t *add_subtract_argv[] = { &ma_region, &ma_region, NULL };
menu_entry_t m_add = {
			.cmd = "add",
			.help = "add second region to first region",
			.usage = " <region> <region> ",
			.description = NULL,
			.min_argc = 2,
			.argv = add_subtract_argv,
			.func = menu_add
};

menu_entry_t m_subtract = {
			.cmd = "subtract",
			.help = "subtract second region from first region",
			.usage = " <region> <region> ",
			.description = NULL,
			.min_argc = 2,
			.argv = add_subtract_argv,
			.func = menu_subtract
};

menu_arg_t *import_export_argv[] = { &ma_aspect, &ma_filename, NULL };
menu_entry_t m_import = {
			.cmd = "import",
			.help = "load image file onto aspect",
			.usage = " <aspect> <filename> ",
			.description = NULL,
			.min_argc = 2,
			.argv = import_export_argv,
			.func = menu_import
};

menu_entry_t m_export = {
			.cmd = "export",
			.help = "write aspect image to file",
			.usage = " <aspect> <filename> ",
			.description = NULL,
			.min_argc = 2,
			.argv = import_export_argv,
			.func = menu_export
};

menu_arg_t *passphrase_argv[] = { &ma_aspect, &ma_passphrase, NULL };
menu_entry_t m_passphrase = {
			.cmd = "passphrase",
			.help = "change aspect passphrase",
			.usage = " <aspect> [passphrase] ",
			.description = NULL,
			.min_argc = 2,
			.argv = passphrase_argv,
			.func = menu_passphrase
};

menu_arg_t *new_argv[] = { &ma_region, &ma_blocks, &ma_name, &ma_passphrase, NULL };
menu_entry_t m_new = {
			.cmd = "new",
			.help = "create new aspect",
			.usage = " <region> <num/%age> <name> [passphrase] ",
			.description = "\n\
\tCreates aspect, carving num/%age blocks out of specified region.\n\
\tIf passphrase is given as '-', a transparent aspect is created with:\n\
\t\t- a randomised passphrase hash\n\
\t\t- no data block encryption\n\
\tAspects created within a transparent aspect will contain its passphrase\n\
\thash within their header sectors, allowing stegsetup to load both\n\
\taspects when given only the inner aspect passphrase. Transparent aspects\n\
\tare useful for shuffling an entire block device, including regions used\n\
\tby aspects whose presence is unknown. Their use is recommended. A new\n\
\tblock device may be initialised as follows:\n\
\t\terase 0\n\
\t\tnew 0 100% mydrive -\n\
\tThe edit command may then be used to create aspects within this newly\n\
\tcreated transparent aspect.\n",
			.min_argc = 4,
			.argv = new_argv,
			.func = menu_new
};


menu_arg_t *write_argv[] = { &ma_aspect, NULL };
menu_entry_t m_write = {
			.cmd = "write",
			.help = "write changed aspects",
			.usage = " [aspect] ",
			.description = "\n\
\tWrites all changes, for given aspect or for all altered aspects.\n",
			.min_argc = 0,
			.argv = write_argv,
			.func = menu_write
};

menu_entry_t m_forcewrite = {
			.cmd = "forcewrite",
			.help = "write all aspects",
			.usage = NULL,
			.description = "\n\
\tWrites all aspects, including unchanged aspects\n",
			.min_argc = 0,
			.argv = null_argv,
			.func = menu_forcewrite
};

menu_arg_t *set_argv[] = { &ma_set, &ma_value, NULL };
menu_entry_t m_set = {
			.cmd = "set",
			.help = "set parameter, or display current value",
			.usage = " <parameter> [value] ",
			.description = "\n\
\tparameter\tdescription\n\n\
\t    t\t\tnumber of locations at which stegdisk will search for\n\
\t     \t\taspect headers (0 for no limit)\n\
\t    m\t\tmaximum bunny level at which stegdisk will search for\n\
\t     \t\taspect headers\n\
\t    l\t\tnew aspects will use this bunny level\n\
\t    e\t\tnew aspects will be transparent (0) or encrypted (1)\n\
\t    s\t\tnew aspects will be shuffled by stegd (1) or not (0)\n\
\t    b\t\tblock size used by new aspects, in B, KB, or MB\n\
\t    a\t\tatom size used by new aspects, in B or KB\n\
\t    v\t\tstegdisk verbosity level\n",
			.min_argc = 1,
			.argv = set_argv,
			.func = menu_set
};

menu_arg_t *open_argv[] = { &ma_aspect, NULL };
menu_entry_t m_open = {
			.cmd = "open",
			.help = "open aspect",
			.usage = " [aspect] ",
			.description = "\n\
\tOpen aspect for editing. Allows creation of aspects within aspects.\n",
			.min_argc = 0,
			.argv = open_argv,
			.func = menu_open
};

menu_entry_t m_return = {
			.cmd = "return",
			.help = "return from open'ed aspect",
			.usage = NULL,
			.description = NULL,
			.min_argc = 0,
			.argv = null_argv,
			.func = menu_return
};

menu_entry_t *menu[] = {
	&m_help,
	&m_print,
	&m_set,

	&m_aspect,
	&m_open,
	&m_load,
	&m_new,
	&m_import,
	&m_export,
	&m_rename,
	&m_passphrase,
	&m_unload,

	&m_region,
	&m_erase,
	&m_nuke,
	&m_extent,
	&m_split,
	&m_remove,
	&m_add,
	&m_subtract,
	&m_steal,
	&m_metaregion,

	&m_write,
	&m_forcewrite,
	&m_return,
	&m_quit,
	NULL
};

/* UI-oriented menu functions are here, doing-oriented functions are in stegdisk_back.c */

int menu_help(stegdisk_t *sctx, int argc, void **argv)
{
	menu_entry_t **m, **l;
	char *cmd;
	int i, len;
	if(argc) {
		for(m = menu; *m; m++) {
			if(!strcmp(argv[0], (*m)->cmd)) {
				printf("\t%s%s: %s\n%s", (*m)->cmd, (*m)->usage ? (*m)->usage : "", (*m)->help, (*m)->description ? (*m)->description : "");
				break;
			}
		}
		if(!*m) {
			printf("Unknown command: %s\n", (char *)argv[0]);
		}
	} else {
		printf("\tCommand         Description\n\n");
		for(m = menu; *m; m++) {
			for(l = menu, len = 0; *l; l++) {
				if(l != m) {
					for(i = 0; i < strlen((*m)->cmd) && i < strlen((*l)->cmd) && (*m)->cmd[i] == (*l)->cmd[i]; i++) { }
					if(i > len) {
						len = i;
					}
				}
			}
			cmd = steg_malloc(strlen((*m)->cmd) + 3);
			cmd[0] = '[';
			for(i = 1; i < len + 2; i++) {
				cmd[i] = (*m)->cmd[i - 1];
			}
			cmd[i] = ']';
			strcpy(&cmd[i + 1], &(*m)->cmd[len + 1]);
			printf("\t%-15s %s\n", cmd, (*m)->help);
			steg_free(cmd);
		}
		printf("\n\tfor more info: help [command]\n\n");
	}
	steg_free_args(argc, argv);
	return 0;
}

int menu_quit(stegdisk_t *sctx, int argc, void **argv)
{
	int e = MENU_QUIT;
	if(argc) {
		if(!strcmp(argv[0], "!")) {
			goto end;
		}
	}
	if(unwritten_changes(root_ctx)) {
		printf("\tUse 'quit !' to quit without writing changes.\n");
		e = 0;
	}
	end:
	steg_free_args(argc, argv);
	return e;
}

void set_header_data_offset(aspect_t *a, u64 *t, u64 value)
{
	if(value > a->block_bytes) {
		printf("\tFail: offset must be within header block\n");
	} else {
		*t = value;
		a->changes++;
	}
}

void set_boolean(aspect_t *a, u64 *target, char *name, u64 value)
{
	if(value < 2) {
		*target = value;
		a->changes++;
	} else {
		printf("\t%s must be 0 or 1\n", name);
	}
}

int menu_aspect(stegdisk_t *sctx, int argc, void **argv)
{
	int i;
	aspect_t *a;
	u64 value;
	switch(argc) {
	case 0:
		if(sctx->num_aspects) {
			printf("\n\tAspect   Total Bytes    Blocks    Data Bytes     Name\n\n");
			for(i = 0; i < sctx->num_aspects; i++) {
				a = sctx->aspects[i];
				printf("\t%-8i %-14zu %-9zu %-14zu %s\n", i, a->bytes + 2 * a->block_bytes, a->blocks, a->bytes, a->name);
			}
			printf("\n");
		} else {
			printf("\tNo aspects\n");
		}
		break;
	case 1:
		a = sctx->aspects[*(u64 *)argv[0]];
		printf("\tSubstrate:\t\t%s (%s)\n", a->substrate->filename, a->substrate->aspect ? "aspect" : "file/device" );
		printf("\tAspect name:\t\t%s\n", a->name);
		printf("\tHeader version:\t\t%zu\n", a->version);
		printf("\tData blocks:\t\t%zu\n", a->blocks);
		printf("\tBlock size:\t\t%zu\n", a->block_bytes);
		printf("\tAtom size:\t\t%zu\n", a->atom_bytes);
		printf("\tTotal internal size:\t%zu\n", a->bytes);
		printf("\tEncrypted:\t\t%s\n", a->encryption ? "Yes" : "No");
		printf("\tShuffling:\t\t%s\n", a->shuffling ? "Yes" : "No");
		printf("\tJournalling:\t\t%s\n", a->journalling ? "Yes" : "No");
		printf("\tJournal offset:\t\t%zx\n", a->journal_offset);
		printf("\tKeyfrags offset:\t%zx\n", a->keyfrags_offset);
		printf("\tIndex offset:\t\t%zx\n", a->index_offset);
		printf("\tParent level:\t\t%zi %s\n", a->parent_level, a->parent_level == NO_PARENT ? "(No parent)" : "");
		printf("\tBunny level:\t\t%i\n", a->bunny_level);
		printf("\tHeader offset:\t\t%zx\n", get_offset(a, a->header_block));
		printf("\tFree block:\t\t%zx\n", le64toh(a->journal->dst_offset));
		printf("\tShuffles left on layer:\t%zu\n", le64toh(a->journal->shuffles_left));
		break;
	case 2:
		printf("\tBad number of args. type 'help aspect' for help\n");
		break;
	case 3:
		a = sctx->aspects[*(u64 *)argv[0]];
		value = *(u64 *)argv[2];
		switch(((char **)argv)[1][0]) {
		case 'e':
			set_boolean(a, &a->encryption, "Encryption", value);
			break;
		case 's':
			set_boolean(a, &a->shuffling, "Shuffling", value);
			break;
		case 'j':
			set_boolean(a, &a->journalling, "Journalling", value);
			break;
		case 'b':
			if(value > REASONABLE_MAX_LEVEL) {
				printf("\tWarning: %zu seems unreasonably high\n", value);
			}
			a->bunny_level = value;
			a->changes++;
			break;
		case 'o':
			set_header_data_offset(a, &a->journal_offset, value);
			break;
		case 'k':
			set_header_data_offset(a, &a->keyfrags_offset, value);
			break;
		case 'i':
			set_header_data_offset(a, &a->index_offset, value);
			break;
		case 'l':
			a->journal->shuffles_left = htole64(value);
			a->changes++;
			break;
		default:
			printf("\tUnknown attribute. type 'help aspect' for help\n");
			break;
		}
	}
	steg_free_args(argc, argv);
	return 0;
}

int menu_rename(stegdisk_t *sctx, int argc, void **argv)
{
	aspect_t *a = sctx->aspects[*(u64 *)argv[0]];
	memset(a->name, 0, ASPECT_NAME_BYTES);
	strncpy(a->name, argv[1], ASPECT_NAME_BYTES - 1);
	a->changes++;
	steg_free_args(argc, argv);
	return 0;
}

int menu_region(stegdisk_t *sctx, int argc, void **argv)
{
	extent_t *e;
	u64 low, high, bytes;
	int r;
	if(argc) {
		r = *(u64 *)argv[0];
		printf("\tExtents for region %i:\n\n\tBase\t\tLength\t\tLimit\n\n", r);
		for(e = sctx->regions[r]->next; e; e = e->next) {
			printf("\t0x%-13zx 0x%-13zx 0x%zx\n", e->base, e->len, e->base + e->len);
		}
	} else {
		printf("\n\tRegion   Bytes          Density   Base           Limit\n\n");
		for(r = 0; r < sctx->num_regions; r++) {
			for(e = sctx->regions[r], bytes = 0; e; e = e->next) {
				bytes += e->len;
				high = e->base + e->len;
			}
			if(sctx->regions[r]->next) {
				low = sctx->regions[r]->next->base;
			}
			if(bytes) {
				printf("\t%-8i %-14zu %3zu%%      0x%-12zx 0x%zx\n", r, bytes, (100 * bytes) / (high - low), low, high);
			} else {
				printf("\t%-8i %-14zu\n", r, bytes);
			}
		}
		printf("\n");
	}
	steg_free_args(argc, argv);
	return 0;
}

int menu_print(stegdisk_t *sctx, int argc, void **argv)
{
	menu_region(sctx, 0, NULL);
	menu_aspect(sctx, 0, NULL);
	steg_free_args(argc, argv);
	return 0;
}

int menu_set(stegdisk_t *sctx, int argc, void **argv)
{
	u64 value = *(u64 *)argv[1];
	int e = -EINVAL;
	int reading = argc == 1 ? 1 : 0;
	if(strlen(argv[0]) > 1) {
		goto unknown;
	}
	switch(((char **)argv)[0][0]) {
		case 't':
			if(reading) {
				printf("\t%zu\n", sctx->default_max_tries);
				break;
			}
			sctx->default_max_tries = value;
			if(!value) {
				printf("\tWill scan every potential location for valid aspect headers\n");
			} else {
				printf("\tWill scan up to %zu locations for valid aspect headers\n", value);
			}
		break;
		case 'm':
			if(reading) {
				printf("\t%zu\n", sctx->default_max_level);
				break;
			}
			sctx->default_max_level = value;
			printf("\tWill scan for aspect headers up to bunny level %zu\n", value);
			if(value > REASONABLE_MAX_LEVEL) {
				printf("\tWarning: %zu seems unreasonably high\n", value);
				goto fail;
			}
		break;
		case 'b':
			if(reading) {
				printf("\t%zu\n", sctx->default_block_bytes);
				break;
			}
			if(value >> (ffs64(value) - 1) != 1) {
				printf("\tError: block bytes must be a power of 2\n");
				goto fail;
			}
			if(value < MINIMUM_BLOCK_BYTES) {
				printf("\tError: blocks must be at least 64 KB\n");
				goto fail;
			}
			sctx->default_block_bytes = value;
			printf("\tNew aspects will use %zu byte blocks\n", value);
		break;
		case 'a':
			if(reading) {
				printf("\t%zu\n", sctx->default_atom_bytes);
				break;
			}
			if(value >> (ffs64(value) - 1) != 1) {
				printf("\tError: atom bytes must be a power of 2\n");
				goto fail;
			}
			if(value > MAXIMUM_ATOM_BYTES || value < MINIMUM_ATOM_BYTES) {
				printf("\tError: out of range. atoms may be from %i B to %i B\n", MINIMUM_ATOM_BYTES, MAXIMUM_ATOM_BYTES);
				goto fail;
			}
			sctx->default_atom_bytes = value;
			printf("\tNew aspects will use %zu byte atoms\n", value);
		break;
		case 'l':
			if(!reading) {
				sctx->default_bunny_level = value;
			}
			printf("\tNew aspects will use bunny level %zu\n", sctx->default_bunny_level);
			if(sctx->default_bunny_level > REASONABLE_MAX_LEVEL) {
				printf("\tWarning: %zu seems unreasonably high\n", sctx->default_bunny_level);
			}
		break;
		case 'e':
			if(reading) {
				printf("\t%zu\n", sctx->default_encryption);
				break;
			}
			if(value > 1) {
				printf("\tError: encryption is either 0 or 1\n");
				goto fail;
			}
			sctx->default_encryption = value;
			printf("\tNew aspects will be %s\n", value ? "encrypted" : "unencrypted (transparent)");
		break;
		case 's':
			if(reading) {
				printf("\t%zu\n", sctx->default_shuffling);
				break;
			}
			if(value > 1) {
				printf("\tError: shuffling is either 0 or 1\n");
				goto fail;
			}
			sctx->default_shuffling = value;
			printf("\tNew aspects will %sbe shuffled by stegd\n", value ? "" : "NOT ");
		break;
		case 'v':
			if(reading) {
				printf("\t%i\n", default_verbosity);
				break;
			}
			default_verbosity = value;
			printf("\tVerbosity set to %zu\n", value);
		break;
		default:
			unknown:
			printf("\tUnknown parameter: %s. Type 'help set' for info.\n", (char *)argv[0]);
	}
	e += EINVAL;
	fail:
	steg_free_args(argc, argv);
	return e;
}

int menu_return(stegdisk_t *sctx, int argc, void **argv)
{
	steg_free_args(argc, argv);
	return MENU_RETURN;
}

int stegdisk_mainloop(stegdisk_t *);

/* Open the given aspects's context */
int menu_open(stegdisk_t *sctx, int argc, void **argv)
{
	int e;
	e = stegdisk_mainloop(sctx->aspects[*(u64 *)argv[0]]->ctx);
	if(e == MENU_RETURN) {
		e = 0;
	}
	steg_free_args(argc, argv);
	return e;
}

int stegdisk_mainloop(stegdisk_t *sctx)
{
	menu_entry_t *cmd, **m;
	substrate_t *sub;
	void *argv[MAX_ARGS];
	char *s, *saveptr, *buf = steg_malloc(BUFLEN);
	int e, match_len, i, argc, ambiguous, levels;
	for(;;) {
		/* Work out how many aspects we are within; print prompt accordingly */
		for(sub = sctx->substrate, levels = 0; sub->aspect; levels++) {
			sub = sub->aspect->substrate;
		}
		memset(buf, 0, BUFLEN);
		do {
			for(sub = sctx->substrate, i = 0; i < levels; i++) {
				sub = sub->aspect->substrate;
			}
			if(strlen(buf)) {
				strncpy(buf + strlen(buf), ":", BUFLEN - strlen(buf) - 1);
			}
			if(strlen(sub->filename)) {
				strncpy(buf + strlen(buf), sub->filename, BUFLEN - strlen(buf) - 1);
			} else {
				strncpy(buf + strlen(buf), "unnamed", BUFLEN - strlen(buf) - 1);
			}
		} while(levels--);
		printf("%s> ", buf);
		if(fgets(buf, BUFLEN, stdin)) {
			buf[strlen(buf) - 1] = 0;	/* s/LF// */
			strtok_r(buf, " ", &saveptr);
			for(m = menu, cmd = NULL; *m; m++) {
				if(!strcmp((*m)->cmd, buf)) {
					cmd = (*m);
					break;
				}
			}
			/* Autocomplete */
			if(!cmd) {
				for(m = menu, match_len = 0, ambiguous = 0; *m; m++) {
					if(strlen(buf) <= strlen((*m)->cmd)) {
						for(i = 0; i < strlen((*m)->cmd) && i < strlen(buf) && (*m)->cmd[i] == buf[i]; i++) { }
						if(i == match_len && match_len) {
							cmd = NULL;
							ambiguous = 1;
						}
						if(i > match_len && i == strlen(buf)) {
							match_len = i;
							cmd = (*m);
							ambiguous = 0;
						}
					}
				}
			}
			if(cmd) {
				for(argc = 0; cmd->argv[argc]; argc++) {
					s = strtok_r(NULL, " ", &saveptr);
					if(s) {
						if(!(argv[argc] = cmd->argv[argc]->parse(sctx, s))) {
							goto badargs;
						}
					} else {
						if(argc < cmd->min_argc) {
							if(!(argv[argc] = cmd->argv[argc]->prompt(sctx))) {
								goto badargs;
							}
						} else {
							break;
						}
					}
				}
				e = cmd->func(sctx, argc, argv);
				if(e == MENU_RETURN || e == MENU_QUIT) {
					break;
				}
				goto next;
			}
			s = ambiguous ? "Ambiguous" : "Unknown";
			printf("\t%s command. type help for help.\n", s);
			goto next;
			badargs:
			printf("\tInvalid arguments.\n");
			next:;
		}
	}
	steg_free(buf);
	return e;
}

stegdisk_t *new_root_ctx(substrate_t *substrate)
{
	stegdisk_t *sctx = steg_calloc(1, sizeof(stegdisk_t));
	sctx->substrate = substrate;
	sctx->default_max_tries = DEFAULT_MAX_TRIES;
	sctx->default_max_level = DEFAULT_MAX_LEVEL;
	sctx->default_block_bytes = steg_default_block_bytes(substrate->bytes);
	sctx->default_atom_bytes = DEFAULT_ATOM_BYTES;
	sctx->default_bunny_level = DEFAULT_BUNNY_LEVEL;
	sctx->default_encryption = 1;
	sctx->default_shuffling = 1;
	sctx->default_journalling = 1;
	add_region(sctx, ext_new(NULL, NULL, 0, substrate->bytes));
	return sctx;
}

int main(int argc, char *argv[])
{
	substrate_t *substrate;
	if(argc<2) {
		printf("Usage: %s <device/file>\n", argv[0]);
		exit(1);
	}
	if(mlockall(MCL_CURRENT | MCL_FUTURE)) {
		printf("\tWarning: mlockall() failed. Secrets may be leaked.\n");
	}
	ramlist_init();
	initialise_random();
	EVP_xts = EVP_STEG_CIPHER;
	if(!(substrate = open_substrate(argv[1]))) {
		die("open_substrate()");
	}
	if(strstr(substrate->filename, "dev/") && strstr(substrate->filename, "steg")) {
		printf("\tWarning: substrate appears to be steg device. Use stegdisk directly\n\ton the original (non-steg) device\n");
	}
	if(!substrate->is_block_device) {
		printf("\tWarning: Substrate is file (potentially insecure)\n");
	}
	verbose_printf("\tSubstrate is %zu bytes\n", substrate->bytes);
	root_ctx = new_root_ctx(substrate);
	stegdisk_mainloop(root_ctx);
	fsync(root_ctx->substrate->handle);
	free_ctx(root_ctx);
	return 0;
}
