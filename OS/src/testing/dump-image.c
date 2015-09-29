#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <fcntl.h>
#include <ctype.h>
#include <assert.h>
#include <errno.h>

#include "gfs2.h"

#include <geekos/vfs.h>
#include <geekos/blockdev.h>
#include <geekos/bitset.h>


struct GFS2_Instance;
extern struct gfs2_inode *clone_inode_for_inum(struct GFS2_Instance *instance,
                                               gfs2_inodenum inum);
extern void read_into_buffer(struct GFS2_Instance *instance,
                             const struct gfs2_inode *inode,
                             unsigned int begin_offset,
                             unsigned int end_offset, void *buffer);


static struct gfs2_dirent *gfs2_make_dirent(gfs2_inodenum inum,
                                            const char *name)
    __attribute__ ((unused));
static struct gfs2_dirent *gfs2_make_dirent(gfs2_inodenum inum,
                                            const char *name) {
    struct gfs2_dirent *de =
        malloc(sizeof(struct gfs2_dirent) + strlen(name) + 3);
    assert(de);
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

void *in_use_bits;
extern struct Filesystem_Ops *gfs2_ops;
extern void setup_device_mmap(const char *filename, int blocksize, int pages);

const char *stringify_rc(int rc) {
    static char errbuf[128];
    if (rc == 0) {
        return "success";
    } else {
        sprintf(errbuf, "%d", rc);
        return errbuf;
    }
}

int recursive_dump(struct Mount_Point *mount_point, const char *root_path) {
    struct File *directory, *realfile;
    int rc, i;

    directory = NULL;
    rc = (mount_point->ops->Open_Directory) (mount_point, root_path,
                                             &directory);
    printf("diropen %s: %s\n", root_path, stringify_rc(rc));
    if (rc < 0)
        exit(EXIT_FAILURE);

    /* struct File_Ops {
       int (*FStat)(struct File *file, struct VFS_File_Stat *stat);
       int (*Read)(struct File *file, void *buf, ulong_t numBytes);
       int (*Write)(struct File *file, void *buf, ulong_t numBytes);
       int (*Seek)(struct File *file, ulong_t pos);
       int (*Close)(struct File *file);
       int (*Read_Entry)(struct File *dir, struct VFS_Dir_Entry *entry);  
       };
     */
    struct VFS_Dir_Entry entry;
    struct VFS_File_Stat stat;
    //{
    //  int size;
    // int isDirectory:1;
    //  int isSetuid:1;
    //  struct VFS_ACL_Entry acls[VFS_MAX_ACL_ENTRIES];
    //};

    char realname[2048];
    for (i = 1;
         (rc =
          (directory->ops->Read_Entry) (directory,
                                        &entry)) != VFS_NO_MORE_DIR_ENTRIES;
         i++) {
        printf("readent %s: %s\n", root_path, stringify_rc(rc));
        if (rc < 0)
            exit(EXIT_FAILURE);
        printf("entry %d: %s\n", i, entry.name);

        strcpy(realname, root_path);
        if (root_path[strlen(root_path) - 1] != '/') {
            strcat(realname, "/");
        }
        strcat(realname, entry.name);
        rc = (mount_point->ops->Stat) (mount_point, realname, &stat);
        printf("stat %s: %d\n", realname, rc);

        if (stat.isDirectory) {
            if (strcmp(entry.name, ".") == 0) {
                printf("is this directory\n");

                if (directory->filePos != 8) {
                    printf
                        ("WARNING, file position is %lu when it should probably be 8.\n",
                         directory->filePos);
                }
            } else if (strcmp(entry.name, "..") == 0) {
                printf("is the parent directory\n");
            } else {
                printf("is another directory; traversing.\n");
                recursive_dump(mount_point, realname);
            }
        } else if (strcmp(entry.name, ".") == 0) {
            /* unlikely, but possible I guess. */
            printf
                ("ERROR:  '%s' should not be a file, it must be a directory.\n",
                 realname);
        } else if (strcmp(entry.name, "..") == 0) {
            /* unlikely, but possible I guess. */
            printf
                ("ERROR:  '%s' should not be a file, it must be a directory.\n",
                 realname);
        } else {
            printf("is a file, opening\n");
            rc = (mount_point->ops->Open) (mount_point, realname, O_READ,
                                           &realfile);
            printf("open %s: %d\n", realname, rc);

            if (rc > 0) {

#define min(a,b) (((a)<(b))?(a):(b))
#define chars_per_line 24
                rc = 1;
                while (rc > 0) {
                    char buffer[chars_per_line];
                    rc = (realfile->ops->Read) (realfile, buffer,
                                                chars_per_line);
                    int ch;
                    for (ch = 0; ch < min(chars_per_line, rc); ch++) {
                        printf("%02x ", buffer[ch]);
                    }
                    for (; ch < chars_per_line; ch++) {
                        printf("   ");
                    }
                    for (ch = 0; ch < min(chars_per_line, rc); ch++) {
                        if (isprint(buffer[ch])) {
                            printf("%c", buffer[ch]);
                        } else {
                            printf(".");
                        }
                    }
                    printf("\n");
                }
            }
        }
        assert(directory);
        if (directory->filePos + 8 > directory->endPos &&
            directory->filePos != directory->endPos) {
            printf
                ("ERROR: inconsistency in file position.  Unlikely that after reading an entry, the next one will be at position %lu when the end of file is at %lu\n",
                 directory->filePos, directory->endPos);
            exit(EXIT_FAILURE);
        }
    }
    return i - 1;               /* the number of entries found.  should be two for the directories. */
}


int main(int argc, const char *argv[]) {
    unsigned int i;             // ,j,d;
    // gfs2_inodenum inum;
    struct gfs2_superblock the_super;
    struct gfs2_superblock *the_super_replica;
    struct Block_Device fake_device;
    struct Mount_Point mount_point;
    FILE *quick_read;
    char block_buffer[4096];
    int rc;

    if (argc < 2) {
        printf("usage: dump-image diskimage\n");
        exit(EXIT_FAILURE);
    }

    quick_read = fopen(argv[1], "r");
    if (quick_read == NULL) {
        printf("unable to open %s, %s\n", argv[1], strerror(errno));
        exit(EXIT_FAILURE);
    }
    rc = fseek(quick_read, 1024, SEEK_SET);
    if (rc != 0) {
        printf("fseek to the superblock failed in %s, %s\n", argv[1],
               strerror(errno));
        exit(EXIT_FAILURE);
    }

    rc = fread(&the_super, sizeof(the_super), 1, quick_read);
    if (rc <= 0) {
        printf("superblock read failed in %s, %s\n", argv[1],
               strerror(errno));
        exit(EXIT_FAILURE);
    }
    fclose(quick_read);

    printf("block_size: %d\n", the_super.block_size);

    setup_device_mmap(argv[1], the_super.block_size,
                      the_super.blocks_per_disk);

    /* dump superblock */
    printf("superblock: **********************************\n");
    printf(" gfs2_magic: 0x%x %s\n", the_super.gfs2_magic, (the_super.gfs2_magic == 0x47465332) ? "good" : "*FAIL*");   /* 0x47465332 */
    printf(" gfs2_version: 0x%x %s\n", the_super.gfs2_version, (the_super.gfs2_version == 0x0100) ? "good" : "*FAIL*"); /* 0x00000100 */
    printf(" block_size: %u\n", the_super.block_size);  /* 512, 1024, 4096 */
    printf(" blocks_per_disk: %u\n", the_super.blocks_per_disk);        /* variable */
    printf(" block_with_inode_zero: %u\n", the_super.block_with_inode_zero);    /* likely 4 if 512 is the block size, smaller if larger. */
    printf(" number_of_inodes: %u\n", the_super.number_of_inodes);      /* calculated on format */
    printf(" replica_superblock_addresses[0]: %u\n",
           the_super.replica_superblock_addresses[0]);

    if (the_super.block_size >= 512 &&
        the_super.replica_superblock_addresses[0] > 0) {
        /* check replica */
        Block_Read(NULL,
                   the_super.replica_superblock_addresses[0] *
                   (the_super.block_size / 512), block_buffer);
        the_super_replica = (struct gfs2_superblock *)block_buffer;

        printf("superblock replica: **********************************\n");
        printf(" gfs2_magic: 0x%x %s\n", the_super_replica->gfs2_magic, (the_super_replica->gfs2_magic == 0x47465332) ? "good" : "*FAIL*");     /* 0x47465332 */
        printf(" gfs2_version: 0x%x %s\n", the_super_replica->gfs2_version, (the_super_replica->gfs2_version == 0x0100) ? "good" : "*FAIL*");   /* 0x00000100 */
    } else {
        printf
            ("invalid superblock information, not looking for superblock replica.");
    }

    if (the_super.number_of_inodes < 2) {
        printf("ERROR: unable to continue.  file system has only %d inodes",
               the_super.number_of_inodes);
        exit(EXIT_FAILURE);
    }

    Init_GFS2();

    /* dump recursive tree */
    memset(&fake_device, 0, sizeof(fake_device));
    mount_point.dev = &fake_device;     /* not null */
    mount_point.pathPrefix = (char *)"";        /* warning avoidance */
    mount_point.fsData = NULL;
    mount_point.ops = NULL;
    fake_device.inUse = 1;

    KASSERT(gfs2_ops);

    rc = (gfs2_ops->Mount) (&mount_point);
    printf("mounting: %d %p\n", rc, mount_point.fsData);
    if (rc < 0)
        exit(EXIT_FAILURE);

    //    int (*Open)(struct Mount_Point *mountPoint, const char *path, int mode, struct File **pFile);
    //  int (*Create_Directory)(struct Mount_Point *mountPoint, const char *path);
    //  int (*Open_Directory)(struct Mount_Point *mountPoint, const char *path, struct File **pDir);
    //  int (*Stat)(struct Mount_Point *mountPoint, const char *path, struct VFS_File_Stat *stat);
    //  int (*Sync)(struct Mount_Point *mountPoint);
    //  int (*Delete)(struct Mount_Point *mountPoint, const char *path);

    int dirs = recursive_dump(&mount_point, "/");

    struct gfs2_inode *inode = clone_inode_for_inum(mount_point.fsData, 2);
    if (inode == NULL) {
        printf("no free blocks inode?\n");
        exit(EXIT_FAILURE);
    }
    if (inode->inum_self != 2) {
        printf("free blocks inode has inode number %d?\n", inode->inum_self);
        exit(EXIT_FAILURE);
    }
    int expected_size =
        (the_super.blocks_per_disk & 0x7) ? (the_super.blocks_per_disk / 8 +
                                             1) : (the_super.blocks_per_disk /
                                                   8);
    if (expected_size != inode->size) {
        printf("ERROR: bad size of the free blocks bitmap: %d expecting %d",
               inode->size, expected_size);
    } else {
        printf("Free blocks bitmap size is correct\n");
    }
    void *buf = malloc(inode->size);
    read_into_buffer(mount_point.fsData, inode, 0, inode->size, buf);
    printf("Free: ");
    for (i = 0; i < inode->size; i++)
        printf("%02x", ((unsigned char *)buf)[i]);
    printf("\n");

    /* check free bitmap */

    if (dirs == 0) {
        printf("Root directory busted or missing entries\n");
        exit(EXIT_FAILURE);
    }

    exit(EXIT_SUCCESS);
}

int Get_CPU_ID() {
    return 0;
}

struct Kernel_Thread *g_currentThreads[16];

void Spin_Lock(Spin_Lock_t * dummy) {
    return;
}
void Spin_Unlock(Spin_Lock_t * dummy) {
    return;
}
