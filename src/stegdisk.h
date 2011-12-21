/* stegdisk.h - included by stegdisk.c */

#define MAX_ARGS	16
#define MENU_RETURN	0xc3
#define MENU_QUIT	0xcb

typedef struct extent_t extent_t;

struct extent_t {
	extent_t *next;
	extent_t *prev;
	u64 base;
	u64 len;
};

struct stegdisk_t {
	substrate_t *substrate;

	extent_t **regions;
	int num_regions;
	aspect_t **aspects;
	int num_aspects;

	u64 default_max_tries;
	u64 default_max_level;
	u64 default_block_bytes;
	u64 default_atom_bytes;
	u64 default_bunny_level;
	u64 default_encryption;
	u64 default_shuffling;
	u64 default_journalling;
};

typedef void *(menu_parse_t)(stegdisk_t *, char *);
typedef void *(menu_prompt_t)(stegdisk_t *);

typedef struct {
	menu_parse_t *parse;
	menu_prompt_t *prompt;
} menu_arg_t;

typedef int(menu_function_t)(stegdisk_t *, int, void **);

typedef struct {
	char *cmd;
	char *help;
	char *usage;
	char *description;
	int min_argc;
	menu_arg_t **argv;
	menu_function_t *func;
} menu_entry_t;

extern stegdisk_t *root_ctx;

menu_function_t	menu_help;
menu_function_t	menu_quit;
menu_function_t	menu_load;
menu_function_t	menu_aspect;
menu_function_t	menu_region;
menu_function_t	menu_print;
menu_function_t	menu_new;
menu_function_t	menu_erase;
menu_function_t	menu_import;
menu_function_t	menu_export;
menu_function_t	menu_write;
menu_function_t	menu_set;
menu_function_t	menu_split;
menu_function_t	menu_passphrase;
menu_function_t	menu_unload;
menu_function_t	menu_remove;
menu_function_t	menu_add;
menu_function_t	menu_subtract;
menu_function_t	menu_open;
menu_function_t	menu_return;
menu_function_t	menu_steal;
menu_function_t	menu_forcewrite;
menu_function_t	menu_metaregion;
menu_function_t	menu_rename;
menu_function_t	menu_nuke;
menu_function_t	menu_extent;

u64		steg_default_block_bytes(u64);
void		delete_region(stegdisk_t *, int);
void		free_ctx(stegdisk_t *);
void		free_aspect(aspect_t *);
void		remove_aspect_from_ctx(stegdisk_t *, aspect_t *);
extent_t	*add_region(stegdisk_t *, extent_t *);
int		unwritten_changes(stegdisk_t *);

void		free_region(extent_t *);
extent_t	*ext_new(extent_t *, extent_t *, u64, u64);
extent_t	*ext_new_head(void);
extent_t	*ext_insert_after(extent_t *, u64, u64);
extent_t	*ext_split(extent_t *, u64);
int		ext_contains_range(extent_t *, u64, u64);
extent_t	*ext_subtract(extent_t *, u64, u64);
extent_t	*ext_subtract_regions(extent_t *, extent_t *);
extent_t	*ext_add(extent_t *, u64, u64);
void		ext_add_regions(extent_t *, extent_t *);
void		ext_subtract_bitmap(extent_t *, u64 *, u64, u64);
void		ext_add_bitmap(extent_t *, u64 *, u64, u64);
void		ext_set_bitmap(u64 *, extent_t *, u64);
u64		bitmap_bits(u64 *, u64);
void		bitmap_set(u64 *, u64);
u64		*bitmap_create_blocklist(u64 *, u64, u64);
void		bitmap_clear(void *, u64);
void		*bitmap_new(u64);
void		bitmap_free(void *);
void		bitmap_populate(void *, aspect_t *);
