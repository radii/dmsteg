/* steg.h - included by all userland .c files. Largely the same as the kernel's dm-steg.h */
#include <openssl/evp.h>

#define EVP_STEG_CIPHER		EVP_aes_128_xts()
#define steg_cipher_ctx		EVP_CIPHER_CTX
#define steg_cipher		EVP_Cipher
#define steg_cipher_ctx_cleanup EVP_CIPHER_CTX_cleanup
#define ENCRYPT			1
#define DECRYPT			0

#define SECTOR_BYTES		512
#define MINIMUM_ATOM_BYTES	SECTOR_BYTES
#define MAXIMUM_ATOM_BYTES	4096
#define MINIMUM_BLOCK_BITS	16
#define MINIMUM_BLOCK_BYTES	(1 << MINIMUM_BLOCK_BITS)	/* Aspect and substrate headers have to be aligned on this boundary */
#define DEFAULT_ATOM_BYTES	4096
#define DEFAULT_BLOCK_BYTES	MINIMUM_BLOCK_BYTES
#define ASPECT_NAME_BYTES	64
#define ASPECT_NAME_SCANF	"%63s"

#define IVEC_BYTES		16
#define KEY_BYTES		32	/* 256-bit */
#define SALT_BYTES		56	/* Not always all used */
#define META_HASH_BYTES		24
#define SHA512_BLOCK_BYTES	128	/* 1024-bit */

#define DEFAULT_BUNNY_LEVEL	1
#define TRANSPARENT_BUNNY_LEVEL	0
#define DEFAULT_MAX_LEVEL	1
#define REASONABLE_MAX_LEVEL	4
#define DEFAULT_MAX_TRIES	200
#define BUNNY_ENTRY_BYTES	64
#define U64S_PER_ENTRY		(BUNNY_ENTRY_BYTES / 8)
#define LEVEL0_BITS		16
#define LEVEL0_ENTRIES		(1 << 16)
#define LEVEL0_GENERATE_HOPS	(LEVEL0_ENTRIES * 4)
#define LEVEL0_CALCULATE_HOPS	(LEVEL0_ENTRIES / 4)
#define LEVEL0_TOTAL_BYTES	(BUNNY_ENTRY_BYTES * LEVEL0_ENTRIES)
#define TRUE			1
#define FALSE			0

#define ASPECT_HEADER_VERSION	1
#define STEGD_VERSION_STRING	"1"

#define PASSPHRASE_SALT		0x13, 0x1f, 0xcc, 0xd4, 0x7f, 0xc7, 0xe4, 0x37, 0xf2, 0x75, 0x3a, 0xae, 0x7c, 0x20, 0xe8, 0x77, 0xdf, 0x61, 0x0b, 0x0a, 0x80, 0x6f, 0x70, 0xad, 0x8f, 0x27, 0xf0, 0x44, 0xe4, 0x6c, 0xf7, 0x30
/* hash of "-" */
#define TRANSPARENT_HASH	0x3a, 0xc1, 0x44, 0x3b, 0xc4, 0xcd, 0x4c, 0x68, 0xdc, 0x98, 0x34, 0x04, 0x95, 0x23, 0x38, 0xbf, 0x8b, 0x55, 0x3d, 0x19, 0xdf, 0xc5, 0xc9, 0xd8, 0x2e, 0x60, 0x31, 0x22, 0x0e, 0xc8, 0x44, 0x67

#define CHUNK_BYTES		131072

#define NO_PARENT		-1

#define MESG_STR(x)		x, sizeof(x)

#define BUFLEN			4096
#define STEGD_SOCKET		"/var/run/stegd"

#define verbose_printf		if(default_verbosity) printf

/* All u64's are little endian when written to disk and in block_t */
typedef u_int64_t u64;
typedef u_int32_t u32;
typedef u_int16_t u16;
typedef unsigned char u8;

/* for stegd */
typedef struct {
	u64 id;
	char *path;
	char *substrate;
	int shuffling;
	int bunny_level;
	u64 blocks;
	u64 block_bytes;
	u8 passphrase_hash[KEY_BYTES];
	u8 bunny_seed[BUNNY_ENTRY_BYTES];
	u8 salt[SALT_BYTES];
} steg_device_t;

typedef struct {
	u8 d[KEY_BYTES];
} keyfrag_t;

/* block_t is used to map from offset into aspect to offset into block device */
/* in-memory format identical to on-disk format. */
#define REST_OF_KEY_BYTES	(KEY_BYTES - sizeof(u64))
typedef struct {
	u64 offset;
	u8 rest_of_keyfrag[REST_OF_KEY_BYTES];
} block_t;

/* pyramid format: upper 2 bits: 01 = data block, 10 = index block, 11 = the header block. lower 62 bits = block number within index */
#define MAX_LAYERS		(65 - MINIMUM_BLOCK_BITS)
#define pyramid_type(x)		((x)&((u64)3<<62))
#define pyramid_blocknum(x)	((x)&~((u64)3<<62))
#define PYRAMID_HEADER		((u64)2<<62)
#define PYRAMID_DATA		((u64)1<<62)
typedef u64 pyramid_t;
#define PYRAMID_T_PER_PAGE	(PAGE_SIZE/8)

typedef struct aspect_t aspect_t;

/* Describes the device/file/aspect on which a given aspect resides */
typedef struct substrate_t substrate_t;
struct substrate_t {
	aspect_t *aspect;		/* NULL if substrate is device or file */
	int handle;
	char *filename;			/* Or aspect name */
	int is_block_device;
	u64 bytes;			/* Total bytes on device */
};

/* journal logs shuffles to avoid data loss or metadata corruption if power failure occurs */
/* journal also keeps track of alignment pyramid so blocks do not become less aligned */
/* always little-endian, in memory and on disk */
typedef struct {
	pyramid_t block_being_moved;	/* or 0 if none */
	u64 src_offset;			/* offset into block device */
	u64 dst_offset;			/* offset into block device */
	u64 ascending;			/* after layer is done, we move up (TRUE) or down (0) */
	u64 shuffles_left;		/* shuffles left before we move onto next layer */
	pyramid_t promoted[0];
} aspect_disk_journal_t;

typedef struct stegdisk_t stegdisk_t;

/* In-memory structure. u64's are all host byte order */
struct aspect_t {
	substrate_t *substrate;		/* substrate in which this aspect resides */
	stegdisk_t *ctx;		/* for stegdisk - the context inside this aspect */
	int changes;			/* for stegdisk - indicates unwritten changes */

	/* Straight from the on-disk header */
	u64 version;
	u64 sequence;
	u64 blocks;
	u64 block_bytes;
	u64 atom_bytes;
	u64 encryption;
	u64 shuffling;
	u64 journalling;
	u64 journal_offset;
	u64 keyfrags_offset;
	u64 index_offset;
	u64 parent_level;
	u8 parent_passphrase_hash[KEY_BYTES];
	u8 salt[SALT_BYTES];
	char name[ASPECT_NAME_BYTES];

	/* Calculated values that are useful */
	u64 bytes;			/* Total internal size of aspect */
	u64 meta_atom_bytes;		/* atom_bytes minus meta_tail_t */
	u64 block_t_per_meta_atom;
	u64 atoms_per_block;
	u64 offset_mask;

	/* Block lists and keyfrags */
	block_t *header_block;
	block_t header_block_data;	/* block_t for header block */
	aspect_disk_journal_t *journal;
	block_t *block;
	keyfrag_t *atom_keyfrag;

	int bunny_level;
	u8 bunny_seed[BUNNY_ENTRY_BYTES];	/* Given to stegd by stegsetup */
	u8 passphrase_hash[KEY_BYTES];
	u8 header_key[KEY_BYTES];
	u64 header_offset;			/* Within outermost substrate */
};

/* On disk, prefaced by 64B bunny seed. 512 bytes total. */
/* All u64s are little endian */
typedef struct {
	u64 version;				/* Encryption starts here */
	u64 sequence;				/* For choosing between multiple headers */
	u64 blocks;				/* Number of data blocks ... */
	u64 block_bytes;			/* Size of blocks */
	u64 atom_bytes;				/* Size of constituent atoms */
	u64 encryption;				/* For data blocks only */
	u64 shuffling;				/* Boolean */
	u64 journalling;			/* Boolean */
	u64 journal_offset;			/* In bytes, from start of header block */
	u64 keyfrags_offset;			/* ditto */
	u64 index_offset;			/* ditto */
	u64 parent_level;			/* -1 for no parent */

	u8 parent_passphrase_hash[KEY_BYTES];	/* for loading parent */
	block_t header_block_data;		/* for bootstrapping */
	keyfrag_t seed_keyfrag;			/* for bootstrapping */
	u8 salt[SALT_BYTES];			/* for hash input padding */
	char name[ASPECT_NAME_BYTES];		/* Null-terminated; empty space randomised */
	char padding[104];			/* Randomise this */
	u8 inner_hash[32];			/* SHA-256 of plaintext */
} aspect_disk_header_t;

typedef struct {
	u8 hash[META_HASH_BYTES];
	u64 rnd64;
} meta_tail_t;

/* And all the prototypes */

extern int default_verbosity, devrandom, devurandom;
extern const EVP_CIPHER *EVP_xts;

/* aux.c */
void	die(char *);
int	ffs64(u64);
u64	kmgt_multiply(u64, char *);
u64	round_up(u64, u64);
void	sprint_hex(char *, u8 *, int);
void	print_hex(char *, void *, int);
int	read_hex(u8 *, char *, int);
int	randomise(void *, u64);
int	urandomise(void *, u64);
int	initialise_random();

/* bunny.c */
void	steg_cipher_init(steg_cipher_ctx *, u8 *, int);
void	steg_hash_passphrase(u8 *, char *);
int	get_key_hash(u8 *);
void	bunny_hopping(void *, void *, int, int);
void	*bunny_precalculate(u8 *, int);
int	bunny_calculate(u8 *passphrase_hash, int, u8 *, u8 *);

/* file.c */
substrate_t *open_substrate(char *);
int	read_sectors(substrate_t *, u64, u64, void *);
int	read_sector(substrate_t *, u64, void *);
int	write_sectors(substrate_t *, u64, u64, void *);
int	write_sector(substrate_t *, u64, void *);
int	encrypt_and_write_atom(aspect_t *, block_t *, u64, void *);
int	write_data_to_aspect(aspect_t *, block_t *, u64, u64, void *);
int	read_and_decrypt_atom(aspect_t *, block_t *, u64, void *);
int	read_data_from_aspect(aspect_t *, block_t *, u64, u64, void *);
int	file_import_export(int, aspect_t *, char *);

/* core.c */
keyfrag_t *get_keyfrag_for_offset(aspect_t *, u64);
u64	get_offset_of_keyfrag(aspect_t *, u64);
void	set_offset(aspect_t *, block_t *, u64);
u64	get_offset(aspect_t *, block_t *);
u64	get_offset_from_offset(aspect_t *, u64);
u64	get_offset_reverse(aspect_t *a, u64);
u64	get_seed_keyfrag(aspect_t *);
int	write_aspect_header_sector(aspect_t *);
void	get_data_atom_key(aspect_t *, u64, u8 *);
int	write_aspect_journal_atom(aspect_t *);
int	write_aspect_keyfrags(aspect_t *);
int	write_aspect_index_table(aspect_t *);
int	load_aspect_keyfrags(aspect_t *);
int	load_aspect_index_table(aspect_t *);
int	load_aspect_journal(aspect_t *);
aspect_t **load_aspects_headers(substrate_t *, u8 *, int, int, int);

/* ramlist.c */
void	steg_free(void *);
void	steg_free_args(int, void **);
void	ramlist_init(void);
void	*steg_malloc(size_t);
void	*steg_calloc(size_t, size_t);
void	*steg_realloc(void *, size_t);

/* stegd_lib.c */
int	stegd_connect(void);
char	*stegd_test(int, u8 *);
char	*stegd_get_path(int);
int	stegd_add(int, aspect_t *, char *);

/* dm.c */
void	dm_check_version(void);
int	dm_message(char *, char *);
int	dm_bunnypair(char *, u8 *, u8 *, u8 *);
int	dm_umount_aspect(char *);
int	dm_mount_aspect(substrate_t *, u64, u8 *, char *);
