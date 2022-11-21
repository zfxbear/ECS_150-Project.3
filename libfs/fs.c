#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "disk.h"
#include "fs.h"

#define FAT_EOC 0xFFFF

#define fs_error(fmt, ...) \
	fprintf(stderr, "%s: "fmt"\n", __func__, ##__VA_ARGS__)

/*superblock  instance description*/
struct superblock {
	/* Signature (must be equal to “ECS150FS”) */
	uint8_t signature[8];
	/* Total amount of blocks of virtual disk */
	uint16_t total_blocks;
	/* Root directory block index */
	uint16_t root_block_idx;
	/* Data block start index */
	uint16_t data_block_start_idx;
	/* Amount of data blocks */
	uint16_t data_blocks;
	/* Number of blocks for FAT */
	uint8_t  fat_blocks;
	/* Unused/Padding */ 
	uint8_t padding[4079];
}__attribute__((packed));

typedef struct superblock superblock;

/* file entry instance description*/
struct entry {
	/* Filename (including NULL character) */
	uint8_t filename[FS_FILENAME_LEN];
	/* Size of the file (in bytes) */
	uint32_t filesize;
	/* Index of the first data block */
	uint16_t start_data_block;
	/* Unused/Padding */ 
	uint8_t padding[10];
}__attribute__((packed));

typedef struct entry entry;

/* global variables */
/* superblock variable */
superblock superblock_info;

/* fat array */
uint16_t *fats;

/* The root directory is an array of 128 entries */
entry root_directory[FS_FILE_MAX_COUNT];

/* File descriptor operations instance description*/
struct file_desc_operation {
    /* the file entry */ 
    entry *file_entry;
    /* file offset */ 
    size_t offset;
 };

 typedef struct file_desc_operation file_desc;

 
 /* File descriptor array */ 
file_desc fds[FS_OPEN_MAX_COUNT];


/* TODO: Phase 1 */

int fs_mount(const char *diskname)
{
	/* TODO: Phase 1 */
	size_t disk_block_index;
	uint8_t  buf[BLOCK_SIZE];
	size_t i, j, count;

	/* open disk file */
	if (block_disk_open(diskname) == -1) {
		fs_error("virtual disk file %s cannot be opened", diskname);
		return -1;
	}

	disk_block_index = 0;
	/* read super block info */
	if (block_read(0, buf) == -1) {
		fs_error("read super block data fail");
		return -1;
	}
	disk_block_index ++;

	memcpy(&superblock_info, buf, BLOCK_SIZE);

	/* check fs Signature*/
	if (strncmp((char *)superblock_info.signature, "ECS150FS", 8)) {
		fs_error("no ECS150FS signature");
		return -1;
	}

	/* check total block number */
	if (superblock_info.total_blocks != block_disk_count()) {
		fs_error("super block total block number incorrect");
		return -1;
	}

	/* check all block number */
	if (superblock_info.total_blocks != 1 + superblock_info.fat_blocks + 1 + superblock_info.data_blocks) {
		fs_error("super block all block number incorrect");
		return -1;
	}

	/* check root directroy start blcok index */
	if (1 + superblock_info.fat_blocks != superblock_info.root_block_idx) {
		fs_error("super block root directory block index incorrect");
		return -1;
	}

	/* check data block start index */
	if (1 + superblock_info.fat_blocks + 1 != superblock_info.data_block_start_idx) {
		fs_error("super block data block start index incorrect");
		return -1;
	}

	/* read fat array */
	/* init fats */
	fats = (uint16_t *) malloc(superblock_info.data_blocks*sizeof(uint16_t));
	if (fats == NULL) {
		fs_error("init fats array error");
		return -1;
	}

	count = 0;
	for (i = 0; i < superblock_info.fat_blocks; ++i) {
		if (block_read(disk_block_index + i, buf) == -1) {
			fs_error("read fat block data fail");
			return -1;
		}

		for (j = 0; j < BLOCK_SIZE/sizeof(uint16_t) && count < superblock_info.data_blocks; ++j) {
			memcpy(&fats[count], buf + j*sizeof(uint16_t), sizeof(uint16_t));
			count ++;
		}
	}
	disk_block_index += superblock_info.fat_blocks;

	/* read file entry */
	if (block_read(disk_block_index, buf) == -1) {
		fs_error("read root directory block data fail");
		return -1;
	}
	for (i = 0; i < FS_FILE_MAX_COUNT; i ++) {
		memcpy(&root_directory[i], buf + i*sizeof(entry), sizeof(entry));
	}
	
	/* init file descriptor operation */
	for(i = 0; i < FS_OPEN_MAX_COUNT; i++) {
        fds[i].file_entry = NULL;
        fds[i].offset = 0;
    }

	return 0;
}

int fs_umount(void)
{
	/* TODO: Phase 1 */
	uint8_t  buf[BLOCK_SIZE];
	size_t disk_block_index;
	int i,j;

	if (block_disk_count() == -1) {
		fs_error("no FS is currently mounted");
		return -1;
	}

	/* if there are still open file descriptors */
    for (i = 0;  i < FS_OPEN_MAX_COUNT; ++i) {
        if (fds[i].file_entry != NULL) {
			fs_error("there are still open file descriptors");
            return -1;
        }
    }

	/* write fat info */ 
	disk_block_index = 1;
	j = 0;
	memset(buf, 0, sizeof(buf));
	for (i = 0; i < superblock_info.data_blocks; ++i) {
		if (j == BLOCK_SIZE/sizeof(uint16_t)) {
			if (block_write(disk_block_index, buf) == -1) {
				fs_error("write fat data fail");
				return -1;
			}
			j = 0;
			disk_block_index ++;
			memset(buf, 0, sizeof(buf));
		}
		memcpy(buf + j * sizeof(uint16_t), &fats[i], sizeof(uint16_t));
		j ++;
	}

	/* last fat block*/
	if (block_write(disk_block_index, buf) == -1) {
		fs_error("write fat data fail");
		return -1;
	}
	disk_block_index ++;

	/* write root directory */
	memset(buf, 0, sizeof(buf));
	for (i = 0; i < FS_FILE_MAX_COUNT; i ++) {
		memcpy(buf + i*sizeof(entry), &root_directory[i], sizeof(entry));
	}
	if (block_write(disk_block_index, buf) == -1) {
		fs_error("write root directory data fail");
		return -1;
	}

	if (block_disk_close() == -1) {
		fs_error("disk close error");
		return -1;
	}

	free(fats);

	return 0;
}

int fs_info(void)
{
	/* TODO: Phase 1 */
    int free_blocks;
	int free_entrys;
    int i;
    
    if (block_disk_count() == -1) {
		fs_error("no FS is currently mounted");
		return -1;
	}
    
    /* print super info */ 
    printf("FS Info:\n");
    printf("total_blk_count=%i\n",superblock_info.total_blocks);
    printf("fat_blk_count=%i\n",superblock_info.fat_blocks);
	printf("rdir_blk=%i\n",superblock_info.root_block_idx);
	printf("data_blk=%i\n",superblock_info.data_block_start_idx);
	printf("data_blk_count=%i\n",superblock_info.data_blocks);
    
	/* count fat */ 
    free_blocks = 0;
    for (i = 0; i < superblock_info.data_blocks; i++) {
        if (fats[i] == 0) {
            free_blocks++;
        }
    }
    printf("fat_free_ratio=%d/%d\n", free_blocks, superblock_info.data_blocks);
    
	/* count root directory */ 
    free_entrys = 0;
    for (i = 0; i < FS_FILE_MAX_COUNT; ++i) {
        if (root_directory[i].filename[0] == '\0') {
            free_entrys ++;
        }
    }
    printf("rdir_free_ratio=%d/%d\n", free_entrys, FS_FILE_MAX_COUNT);
    
    return 0;
}

int fs_create(const char *filename)
{
	/* TODO: Phase 2 */
	int i;
	int free_entry_index;

	if (block_disk_count() == -1) {
		fs_error("no FS is currently mounted");
		return -1;
	}

	/* check input filename */
	if (NULL == filename || strlen(filename) >= FS_FILENAME_LEN) {
		fs_error("input filename invalid");
		return -1;
	}

	/* if filename already exist */
	for (i = 0 ; i < FS_FILE_MAX_COUNT; ++i) {
		if(strcmp((char *)root_directory[i].filename, filename) == 0) {
			fs_error("filename already exist");
            return -1;
        }
	}

	/* find free entry index */
	for (free_entry_index = 0; free_entry_index < FS_FILE_MAX_COUNT; ++ free_entry_index) {
		if (root_directory[i].filename[0] == '\0') {
            break;
        }
	}

	if (free_entry_index == FS_FILE_MAX_COUNT) {
		fs_error("the root directory already contains FS_FILE_MAX_COUNT files");
        return -1;
	}

	/* update entry info */
	memcpy(root_directory[free_entry_index].filename, filename, strlen(filename) + 1);
    root_directory[free_entry_index].filesize = 0;
    root_directory[free_entry_index].start_data_block = FAT_EOC;
	return 0;
}

int fs_delete(const char *filename)
{
	/* TODO: Phase 2 */
	int i;
	int file_entry_index;
	uint8_t  buf[BLOCK_SIZE];
	uint16_t data_block_index;
	uint16_t tmp;

	if (block_disk_count() == -1) {
		fs_error("no FS is currently mounted");
		return -1;
	}

	/* check input filename */
	if (NULL == filename || strlen(filename) >= FS_FILENAME_LEN) {
		fs_error("input filename invalid");
		return -1;
	}

	/* if filename no exist */
	for (i = 0 ; i < FS_FILE_MAX_COUNT; ++i) {
		if(strcmp((char *)root_directory[i].filename, filename) == 0) {
			file_entry_index = i;
			break;
        }
	}
	if (i == FS_FILE_MAX_COUNT) {
		fs_error("there is no file named @filename to delete");
		return -1;
	}

	/* if file @filename is currently open */
	for (i = 0; i < FS_OPEN_MAX_COUNT; ++i) {
        if (fds[i].file_entry != NULL && fds[i].file_entry == &root_directory[file_entry_index]) {
			fs_error("file %s is currently open", filename);
            return -1;
        }
    }

	/* delete file data */
	memset(buf, 0 , sizeof(buf));
	data_block_index = root_directory[file_entry_index].start_data_block;
	while (data_block_index != FAT_EOC) {
		if (block_write(superblock_info.data_block_start_idx + data_block_index, buf) == -1) {
			fs_error("write buf to data block fail");
			return -1;
		}
		tmp = data_block_index;
		data_block_index = fats[data_block_index];
		fats[tmp] = 0;
	}

	/* update root directory */
	root_directory[file_entry_index].filename[0] = '\0';
	return 0;
}

int fs_ls(void)
{
	/* TODO: Phase 2 */
	int i;

	if (block_disk_count() == -1) {
		fs_error("no FS is currently mounted");
		return -1;
	}

	printf("FS Ls:\n");
    for (i = 0; i < FS_FILE_MAX_COUNT; ++i) {
        if (root_directory[i].filename[0] != '\0') {
            printf("file: %s, size: %i, data_blk: %i\n", (char *)root_directory[i].filename, 
                root_directory[i].filesize, root_directory[i].start_data_block);
        }
    }
    return 0;
}

int fs_open(const char *filename)
{
	/* TODO: Phase 3 */
	int file_entry_index;
	int i, fd;

	if (block_disk_count() == -1) {
		fs_error("no FS is currently mounted");
		return -1;
	}

	/* check input filename */
	if (NULL == filename || strlen(filename) >= FS_FILENAME_LEN) {
		fs_error("input filename invalid");
		return -1;
	}

	/* find file entry */
	for (i = 0 ; i < FS_FILE_MAX_COUNT; ++i) {
		if(strcmp((char *)root_directory[i].filename, filename) == 0) {
			file_entry_index = i;
			break;
		}
	}
	if (i == FS_FILE_MAX_COUNT) {
		fs_error("there is no file named @filename to open");
		return -1;
	}

	/* find file descriptor */
	for (i = 0; i < FS_OPEN_MAX_COUNT; i++) {
        if (fds[i].file_entry == NULL) {
            fd = i;
            break;
        }
    }
	if (i == FS_OPEN_MAX_COUNT) {
		fs_error("there are already FS_OPEN_MAX_COUNT files currently open");
		return -1;
	}

	fds[fd].file_entry = &root_directory[file_entry_index];
	fds[fd].offset = 0;
	
	return fd;
}

int fs_close(int fd)
{
	/* TODO: Phase 3 */
	if (block_disk_count() == -1) {
		fs_error("no FS is currently mounted");
		return -1;
	}

	/* check fd is valid */
	if (fd < 0 || fd >= FS_OPEN_MAX_COUNT || fds[fd].file_entry == NULL) {
		fs_error("file descriptor @fd is invalid (out of bounds or not currently open)");
        return -1;
    }
    
    fds[fd].file_entry = NULL;
	fds[fd].offset = 0;

	return 0;
}

int fs_stat(int fd)
{
	/* TODO: Phase 3 */
	if (block_disk_count() == -1) {
		fs_error("no FS is currently mounted");
		return -1;
	}

	/* check fd is valid */
	if (fd < 0 || fd >= FS_OPEN_MAX_COUNT || fds[fd].file_entry == NULL) {
		fs_error("file descriptor @fd is invalid (out of bounds or not currently open)");
        return -1;
    }

	return fds[fd].file_entry->filesize;
}

int fs_lseek(int fd, size_t offset)
{
	/* TODO: Phase 3 */
	if (block_disk_count() == -1) {
		fs_error("no FS is currently mounted");
		return -1;
	}

	/* check fd is valid */
	if (fd < 0 || fd >= FS_OPEN_MAX_COUNT || fds[fd].file_entry == NULL) {
		fs_error("file descriptor @fd is invalid (out of bounds or not currently open)");
        return -1;
    }

	/* check input offset*/ 
	if (offset > fds[fd].file_entry->filesize) {
		fs_error("@offset is larger than the current file size");
        return -1;
	}

	fds[fd].offset = offset;
	return 0;
}

int fs_write(int fd, void *buf, size_t count)
{
	/* TODO: Phase 4 */
	uint16_t data_block;
    uint16_t pre_data_block;
	uint16_t start_write_block;
	uint8_t  old_data_buf[BLOCK_SIZE];
	size_t i, j;
	size_t need_blocks;
	size_t actually_write_blocks;
	size_t write_offset;
	size_t write_count;

	if (block_disk_count() == -1) {
		fs_error("no FS is currently mounted");
		return -1;
	}

	/* check fd is valid */
	if (fd < 0 || fd >= FS_OPEN_MAX_COUNT || fds[fd].file_entry == NULL) {
		fs_error("file descriptor @fd is invalid (out of bounds or not currently open)");
        return -1;
    }

	if (buf == NULL) {
		fs_error("@buf is NULL");
		return -1;
	}

	if (count == 0) {
		return 0;
	}

	/* find write data block */
	data_block = fds[fd].file_entry->start_data_block;
	pre_data_block = FAT_EOC;

	for (i = 0; i < fds[fd].offset/BLOCK_SIZE; ++i) {
		pre_data_block = data_block;
		data_block = fats[data_block];
	}
	start_write_block = pre_data_block;

	/* get write count data need data blocks */
	need_blocks = (fds[fd].offset%BLOCK_SIZE + count) / BLOCK_SIZE;
	if ((fds[fd].offset%BLOCK_SIZE + count) % BLOCK_SIZE != 0) {
		need_blocks ++;
	}
	
	/* get actually write data blocks, no data need get new data */
	actually_write_blocks = 0;
	for (i = 0; i < need_blocks; ++i) {
		if (data_block == FAT_EOC) {
			/* need new frree data block */
			for (j = 0; j < superblock_info.data_blocks; ++j) {
				if (fats[j] == 0) {
					break;
				}
			}
			if (j == superblock_info.data_blocks) {
				// no free data block
				break;
			}

			if (pre_data_block == FAT_EOC) {
				fds[fd].file_entry->start_data_block = j;
			}
			else {
				fats[pre_data_block] = j;
			}
			fats[j] = FAT_EOC;
			data_block = j;
		}
		actually_write_blocks ++;
		pre_data_block = data_block;
		data_block = fats[data_block];
	}

	if (start_write_block == FAT_EOC) {
		start_write_block = fds[fd].file_entry->start_data_block;
	}
	else {
		start_write_block = fats[start_write_block];
	}
	
	write_offset = fds[fd].offset%BLOCK_SIZE;
	write_count = 0;
	for (i = 0; i < actually_write_blocks; ++i) {
		/* read data block */
		if (block_read(superblock_info.data_block_start_idx + start_write_block, old_data_buf) == -1) {
			fs_error("read data block error");
			return -1;
		}

		if (count - write_count <= BLOCK_SIZE - write_offset) {
            memcpy(old_data_buf + write_offset, buf + write_count, count - write_count);
            write_count = count;
        }
        else {
            memcpy(old_data_buf + write_offset, buf + write_count, BLOCK_SIZE - write_offset);
			write_count += BLOCK_SIZE - write_offset;
        }

		/* write data block */
		if (block_write(superblock_info.data_block_start_idx + start_write_block, old_data_buf) == -1) {
			fs_error("write data block error");
			return -1;
		}

		// if (write_count == count) {
		// 	break;
		// }

		start_write_block = fats[start_write_block];

		write_offset = 0;
	}

	/* update offset and file size*/
	fds[fd].offset += write_count;

	if (fds[fd].offset > fds[fd].file_entry->filesize) {
		fds[fd].file_entry->filesize = fds[fd].offset;
	}

	return write_count;
}

int fs_read(int fd, void *buf, size_t count)
{
	/* TODO: Phase 4 */
	uint16_t data_block;
	uint8_t  old_data_buf[BLOCK_SIZE];
	size_t i;
	size_t read_count;
	size_t read_offset;
	size_t max_read_size;

	if (block_disk_count() == -1) {
		fs_error("no FS is currently mounted");
		return -1;
	}

	/* check fd is valid */
	if (fd < 0 || fd >= FS_OPEN_MAX_COUNT || fds[fd].file_entry == NULL) {
		fs_error("file descriptor @fd is invalid (out of bounds or not currently open)");
        return -1;
    }

	if (buf == NULL) {
		fs_error("@buf is NULL");
		return -1;
	}

	if (count == 0) {
		return 0;
	}

	/* find read data block */
	data_block = fds[fd].file_entry->start_data_block;

	for (i = 0; i < fds[fd].offset/BLOCK_SIZE; ++i) {
		data_block = fats[data_block];
	}

	/* read data */
	read_offset = fds[fd].offset%BLOCK_SIZE;
	read_count = 0;
	
	while (data_block != FAT_EOC) {
		if (block_read(superblock_info.data_block_start_idx + data_block, old_data_buf) == -1) {
			fs_error("read data block error");
			return -1;
		}

		/* get current read max data size */
		if (fats[data_block] == FAT_EOC) {
			if (fds[fd].file_entry->filesize%BLOCK_SIZE == 0) {
				max_read_size = BLOCK_SIZE - read_offset;
			}
			else {
				max_read_size = fds[fd].file_entry->filesize%BLOCK_SIZE - read_offset;
			}
		}
		else {
			max_read_size = BLOCK_SIZE - read_offset;
		}

		/* read data */
		if (count - read_count <= max_read_size) {
			memcpy(buf+read_count, old_data_buf + read_offset, count - read_count);
			read_count = count;
			break;
		}
		else {
			memcpy(buf+read_count, old_data_buf + read_offset, max_read_size);
			read_count += max_read_size;
		}

		read_offset = 0;
		data_block = fats[data_block];
	}

	/* update offset */
	fds[fd].offset += read_count;

	return read_count;
}

