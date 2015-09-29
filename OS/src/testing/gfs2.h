#ifndef GFS2_H
#define GFS2_H

#include <geekos/vfs.h>
#include <geekos/fileio.h>

/* ==Typedefs== */
typedef unsigned int gfs2_blocknum;     /* For disk block numbers */


typedef unsigned int gfs2_inodenum;     /* For inode numbers */

/* ==Constants== */
#define GFS2_DIRECTORY 1
#define GFS2_FILE 2

#define GFS2_SUPERBLOCK_COPIES 10
#define GFS2_DIRECT_BLOCKS 4

/* Number of block pointers that can be stored in a single indirect filesystem block. */
#define GFS2_PTRS_PER_BLOCK (GFS2_FS_BLOCK_SIZE / sizeof(ulong_t))

/* ==Structures== */
struct gfs2_superblock {
    unsigned int gfs2_magic;    /* 0x47465332 */
    unsigned int gfs2_version;  /* 0x00000100 */
    unsigned int block_size;    /* 512, 1024, 4096 */
    unsigned int blocks_per_disk;       /* variable */
    gfs2_blocknum block_with_inode_zero;        /* likely 4 if 512 is the block size, smaller if larger. */
    unsigned int number_of_inodes;      /* calculated on format */
    gfs2_blocknum replica_superblock_addresses[GFS2_SUPERBLOCK_COPIES];
};

struct gfs2_inode {
    gfs2_inodenum inum_self;    /* implied by location, but included in the inode for ease. */

    unsigned int size;          /* size of the data stored in the direct and indirect blocks  */
    unsigned char type;         /* GOSFS2_DIRECTORY = 1, GOSFS2_FILE = 2, */
    unsigned char reference_count;      /* 1 (for each directory entry pointing to this node, which shall be 1 since we don't link) */
    unsigned short mode;        /* permissions bits; ignore */

    gfs2_blocknum direct_blocks[GFS2_DIRECT_BLOCKS];    /* block numbers for direct blocks */
    gfs2_blocknum indirect_block;       /* block numbers for indirect blocks */
};

struct gfs2_dirent {
    gfs2_inodenum inum;         /* *must* be word-aligned */
    unsigned char entry_length; /* after the inum.  i.e., the min entry length is 4.  max is 252, for alignment */
    unsigned char name_length;  /* may be < entry length - 2. */
    char name[2];               /* where overrun provides the rest of the name; NOT (necessarily) null terminated. */
};

void Init_GFS2(void);

#endif
