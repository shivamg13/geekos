#include <geekos/gfs2.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <fcntl.h>
#include <assert.h>
#include <errno.h>
#include <math.h>

#define GEEKOS
#include <geekos/vfs.h>
#include <geekos/blockdev.h>
#include <geekos/bitset.h>

void setup_device_mmap(const char *filename, int blocksize, int pages);
gfs2_blocknum claim_next_free_block(void);
struct gfs2_superblock the_super;


static struct gfs2_dirent *gfs2_make_dirent(gfs2_inodenum inum,
                                            const char *name) {
    struct gfs2_dirent *de =
        malloc(sizeof(struct gfs2_dirent) + strlen(name) + 3);
    de->inum = inum;
    de->name_length = strlen(name);
    memcpy(de->name, name, de->name_length);
    de->entry_length = de->name_length + 2;
    while (de->entry_length & 0x3) {
        de->entry_length++;     /* round up the lame way */
    }
    return de;
}

void my_size_block_op(char *block_buffer, gfs2_blocknum num,
                      unsigned int blocksize,
                      int (*op) (struct Block_Device * dev, int blockNum,
                                 void *buf)) {
    int sectors_per_block = blocksize / 512;
    int offset = 0;
    int read_sector;
    for (read_sector = num * sectors_per_block, offset = 0;
         read_sector < (num + 1) * sectors_per_block;
         read_sector++, offset += 512) {
        op(NULL, read_sector, &block_buffer[offset]);
    }
}
void my_size_block_reader(char *block_buffer, gfs2_blocknum num,
                          unsigned int blocksize) {
    my_size_block_op(block_buffer, num, blocksize, Block_Read);
}
void my_size_block_writer(char *block_buffer, gfs2_blocknum num,
                          unsigned int blocksize) {
    my_size_block_op(block_buffer, num, blocksize, Block_Write);
}

void append_to_file(struct gfs2_inode *inode, const char *buffer,
                    unsigned int buflen) {
    char *block_buffer = malloc(the_super.block_size);
    printf("trace: append to file inode %d buflen %d\n", inode->inum_self,
           buflen);
    if (inode->size == 0) {
        if (inode->direct_blocks[0] == 0) {
            inode->direct_blocks[0] = claim_next_free_block();
        }
        bzero(block_buffer, the_super.block_size);
    } else {
        assert(inode->size + buflen < the_super.block_size);
        my_size_block_reader(block_buffer, inode->direct_blocks[0],
                             the_super.block_size);
    }

    memcpy(block_buffer + inode->size, buffer, buflen); /* lame version of write. */

    my_size_block_writer(block_buffer, inode->direct_blocks[0],
                         the_super.block_size);

    unsigned int inodes_per_block =
        (the_super.block_size / sizeof(struct gfs2_inode));
    unsigned int inode_block =
        inode->inum_self / inodes_per_block + the_super.block_with_inode_zero;
    my_size_block_reader(block_buffer, inode_block, the_super.block_size);
    inode->size += buflen;
    ((struct gfs2_inode *)(block_buffer))[inode->inum_self %
                                          inodes_per_block].size =
        inode->size;
    ((struct gfs2_inode *)(block_buffer))[inode->inum_self %
                                          inodes_per_block].direct_blocks[0] =
        inode->direct_blocks[0];
    printf("new inode %d size %d\n", inode->inum_self, inode->size);
    my_size_block_writer(block_buffer, inode_block, the_super.block_size);


    free(block_buffer);
}

void *in_use_bits;

gfs2_blocknum claim_next_free_block(void) {
    gfs2_blocknum ret =
        Find_First_Free_Bit(in_use_bits, the_super.blocks_per_disk);
    Set_Bit(in_use_bits, ret);
    return ret;
}

int main(int argc, const char *argv[]) {
    unsigned int i, j, d;
    gfs2_inodenum inum;

    if (argc < 2) {
        printf("usage: image-builder blocksize numblocks files-to-include\n");
        exit(EXIT_FAILURE);
    }

    the_super.block_size = atoi(argv[1]);
    if (the_super.block_size != 512 &&
        the_super.block_size != 1024 && the_super.block_size != 4096) {
        printf("unsupported blocksize: %s\n", argv[1]);
        exit(EXIT_FAILURE);
    }

    the_super.blocks_per_disk = atoi(argv[2]);
    if (the_super.blocks_per_disk < 10) {
        printf("unsupported blocks_per_disk: %s\n", argv[2]);
        exit(EXIT_FAILURE);
    }

    in_use_bits = Create_Bit_Set(the_super.blocks_per_disk);

#ifdef INUSE_PARANOIA
    printf("in use bits dump\n");
    for (i = 0; i < the_super.blocks_per_disk; i++) {
        printf("%c", Is_Bit_Set(in_use_bits, i) ? '!' : '.');
    }
    printf("\n");
    printf("end in use bits dump\n");
#endif

    Set_Bit(in_use_bits, 0);


    the_super.gfs2_magic = 0x47465332;
    the_super.gfs2_version = 0x100;

    Set_Bit(in_use_bits, 0);
    if (the_super.block_size == 512) {
        the_super.block_with_inode_zero = 3;
        Set_Bit(in_use_bits, 1);
        Set_Bit(in_use_bits, 2);        /* sb */
    } else {
        if (the_super.block_size == 1024) {
            Set_Bit(in_use_bits, 1);    /* sb */
            the_super.block_with_inode_zero = 2;
        } else {
            the_super.block_with_inode_zero = 1;
        }
    }
    the_super.replica_superblock_addresses[0] = the_super.blocks_per_disk / 2;
    for (i = 1; i < GFS2_SUPERBLOCK_COPIES; i++)
        the_super.replica_superblock_addresses[i] = 0;

    unsigned int num_inodes_2009 =
        ceil((float)the_super.blocks_per_disk / 10.0);
    unsigned int num_inode_blocks_2009 =
        ceil((float)num_inodes_2009 * sizeof(struct gfs2_inode) /
             (float)the_super.block_size);
    the_super.number_of_inodes =
        num_inode_blocks_2009 * the_super.block_size /
        sizeof(struct gfs2_inode);


    // unsigned int num_inode_blocks= the_super.blocks_per_disk/64;
    // the_super.number_of_inodes=num_inode_blocks * the_super.block_size/sizeof(struct gfs2_inode);
    printf("%d blocks used by inodes -> %d inodes on disk\n",
           num_inode_blocks_2009, the_super.number_of_inodes);

    unsigned int root_directory_block = num_inode_blocks_2009 +
        the_super.block_with_inode_zero;

    unsigned int free_bitmap_block = root_directory_block + 1;
    unsigned int blocks_per_sector = the_super.block_size / 512;

    for (i = 0; i <= free_bitmap_block; i++) {
        Set_Bit(in_use_bits, i);
    }
    Set_Bit(in_use_bits, the_super.blocks_per_disk / 2);

    char filename[255];

    sprintf(filename, "gfs-%dx%d.img", the_super.block_size,
            the_super.blocks_per_disk);

    int fd = open(filename, O_WRONLY | O_CREAT, 0664);
    assert(fd >= 0);
    assert(lseek
           (fd, the_super.block_size * the_super.blocks_per_disk - 1,
            SEEK_SET) > 0);
    if (write(fd, "\0", 1) <= 0) {
        fprintf(stderr, "write off the end failed: %d %s", errno,
                strerror(errno));
        exit(EXIT_FAILURE);
    }
    close(fd);

    setup_device_mmap(filename, the_super.block_size,
                      the_super.blocks_per_disk);


    char block512[512];

    bzero(block512, 512);
    memcpy(block512, &the_super, sizeof(struct gfs2_superblock));
    Block_Write(NULL, 2, block512);
    Block_Write(NULL,
                the_super.blocks_per_disk / 2 * (the_super.block_size / 512),
                block512);

    printf("wrote superblocks\n");

    /* for each sector */
    int i_sector;
    for (i_sector = 0, inum = 0; inum < the_super.number_of_inodes;
         i_sector++) {
        bzero(block512, 512);
        for (j = 0;
             inum < (i_sector + 1) * 512 / sizeof(struct gfs2_inode);
             j++, inum++) {

            if (inum == the_super.number_of_inodes - 1) {
                ((struct gfs2_inode *)block512)[j].inum_self = 0;
            } else if (inum == 0) {
                ((struct gfs2_inode *)block512)[j].inum_self = 0;
            } else {
                ((struct gfs2_inode *)block512)[j].inum_self = inum + 1;
            }

            ((struct gfs2_inode *)block512)[j].size = 0;
            ((struct gfs2_inode *)block512)[j].type = 3;
            ((struct gfs2_inode *)block512)[j].reference_count = 0;
            ((struct gfs2_inode *)block512)[j].mode = 0;
            for (d = 0; d < GFS2_DIRECT_BLOCKS; d++) {
                ((struct gfs2_inode *)block512)[j].direct_blocks[d] = 0;
            }
            ((struct gfs2_inode *)block512)[j].indirect_block = 0;
        }
        printf("writing inode sector %d up to inum %d\n", i_sector, inum);

        Block_Write(NULL, (the_super.block_with_inode_zero *
                           blocks_per_sector) + i_sector, block512);
    }



    Block_Read(NULL, (the_super.block_with_inode_zero *
                      blocks_per_sector + 0), block512);

    ((struct gfs2_inode *)block512)[1].inum_self = 1;
    ((struct gfs2_inode *)block512)[1].type = GFS2_DIRECTORY;
    ((struct gfs2_inode *)block512)[1].reference_count = 1;
    ((struct gfs2_inode *)block512)[1].size = 0;

    Block_Write(NULL, (the_super.block_with_inode_zero *
                       blocks_per_sector + 0), block512);

    struct gfs2_dirent *de = gfs2_make_dirent(1, ".");
    append_to_file(&((struct gfs2_inode *)block512)[1], (char *)de,
                   de->entry_length + 4);
    free(de);
    de = gfs2_make_dirent(1, "..");
    append_to_file(&((struct gfs2_inode *)block512)[1], (char *)de,
                   de->entry_length + 4);
    free(de);
    de = gfs2_make_dirent(3, "hello");
    append_to_file(&((struct gfs2_inode *)block512)[1], (char *)de,
                   de->entry_length + 4);
    free(de);

    Block_Read(NULL, (the_super.block_with_inode_zero *
                      blocks_per_sector + 0), block512);


    ((struct gfs2_inode *)block512)[2].inum_self = 2;
    ((struct gfs2_inode *)block512)[2].type = GFS2_FILE;
    ((struct gfs2_inode *)block512)[2].reference_count = 1;
    ((struct gfs2_inode *)block512)[2].size = 0;

    ((struct gfs2_inode *)block512)[3].inum_self = 3;
    ((struct gfs2_inode *)block512)[3].type = GFS2_FILE;
    ((struct gfs2_inode *)block512)[3].reference_count = 1;
    ((struct gfs2_inode *)block512)[3].size = 0;

    Block_Write(NULL, (the_super.block_with_inode_zero *
                       blocks_per_sector + 0), block512);

    append_to_file(&((struct gfs2_inode *)block512)[3],
                   "this is a file.\n", strlen("this is a file.\n"));


    //   assert (((the_super.blocks_per_disk / 8) + ((the_super.blocks_per_disk % 8 != 0) ? 1 : 0)) <= 512);
#ifdef INUSE_PARANOIA
    printf("in use bits dump\n");
    for (i = 0; i < the_super.blocks_per_disk; i++) {
        printf("%c", Is_Bit_Set(in_use_bits, i) ? '!' : '.');
    }
    printf("\n");
    printf("end in use bits dump\n");
#endif

    append_to_file(&((struct gfs2_inode *)block512)[2],
                   in_use_bits,
                   ((the_super.blocks_per_disk / 8) +
                    ((the_super.blocks_per_disk % 8 != 0) ? 1 : 0)));


    exit(EXIT_SUCCESS);
}
