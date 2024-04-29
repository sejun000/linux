/*
 * Copyright (C) 2003 Jana Saout <jana@saout.de>
 *
 * This file is released under the GPL.
 */

#include <linux/device-mapper.h>

#include <linux/module.h>
#include <linux/init.h>
#include <linux/bio.h>
#include <types.h>

#define SECTORS_PER_PAGE (8)
#define SSD_CAPACITY (32 * 1024 * 1024 * 1024ULL)
#define TOTAL_PHYSICAL_BLOCKS (8192)
#define PAGES_PER_BLOCK (1024)

#define DM_MSG_PREFIX "halfmap"
#define INVALID_MAP (0xFFFFFFFF)
static struct block_device *halfmap_dev;
typedef block_offset_t uint32_t
uint32_t physical_block_map[SSD_CAPACITY / 4096];

struct block_node {
    block_offset_t block_index;
    struct list_head list;
};

struct block_management {
    struct list_head free_blocks;
    struct list_head full_blocks;
    uint16_t write_count[TOTAL_PHYSICAL_BLOCKS];
};

static struct block_management blk_mgmt;


// 블록 관리 초기화
static void initialize_block_management(void) {
    INIT_LIST_HEAD(&blk_mgmt.free_blocks);
    INIT_LIST_HEAD(&blk_mgmt.full_blocks);
    block_offset_t i;
    for (i = 0; i < TOTAL_PHYSICAL_BLOCKS; i++) {
        struct block_node *node = kmalloc(sizeof(struct block_node), GFP_KERNEL);
        if (node) {
            node->block_index = i;
            list_add_tail(&node->list, &blk_mgmt.free_blocks);
        }
        blk_mgmt.write_count[i] = 0;
    }
}

static block_offset_t allocate_new_block(void) {
    spin_lock(&blk_mgmt.lock);
    if (!list_empty(&blk_mgmt.free_blocks)) {
        struct block_node *node = list_first_entry(&blk_mgmt.free_blocks, struct block_node, list);
        list_del(&node->list);
        block_offset_t block_index = node->block_index;
        spin_unlock(&blk_mgmt.lock);
        kfree(node);
        return block_index;
    }
    spin_unlock(&blk_mgmt.lock);
    return INVALID_MAP;
}

static void return_full_block(block_offset_t index) {
    struct block_node *node = kmalloc(sizeof(struct block_node), GFP_KERNEL);
    if (node) {
        node->block_index = index;
        spin_lock(&blk_mgmt.lock);
        list_add_tail(&node->list, &blk_mgmt.full_blocks);
        spin_unlock(&blk_mgmt.lock);
    }
}

// bio_end_io에서 호출될 블록 업데이트 함수
static void update_block_usage(struct bio *bio) {
    struct halfmap_private *pri = bio->bi_private;
    if (bio_data_dir(bio) == WRITE) {
        block_offset_t block_index = pri->phy_blk_addr;
        if (++blk_mgmt.write_count[block_index] >= PAGES_PER_BLOCK) {
            return_full_block(block_index);
            block_offset_t new_block = allocate_new_block();
            if (new_block != INVALID_MAP) {
                pri->phy_blk_addr = new_block;
            } else {
                printk(KERN_ERR "No free blocks available!\n");
            }
        }
    }
}

static int halfmap_ctr(struct dm_target *ti, unsigned int argc, char **argv)
{
    if (argc != 2) {
        ti->error = "Invalid argument count. Expected 2 arguments for read and write devices";
        return -EINVAL;
    }

    if (open_device(argv[1], &halfmap_dev)) {
        ti->error = "Failed to open devices";
        return -EINVAL;
    }
    ti->num_discard_bios = 0;
    return 0;
}

struct halfmap_private {
    block_offset_t phy_blk_addr;
};

// bio_end_io callback function definition
static void halfmap_end_io(struct bio *bio)
{
    struct halfmap_private* pri = bio->bi_private;
    if (bio_data_dir(bio) == WRITE) {
        if (pri == NULL) {
            printk("ERROR for halfmap read\n");
        }
        // mapping table update
        physical_block_map[bio->bi_iter.bi_sector] = pri->phy_blk_addr;
    }
    // free memory
    kfree(phy_blk_addr);
}


/*
 * Return halfmaps only on reads
 */
static int halfmap_map(struct dm_target *ti, struct bio *bio)
{
    struct block_device *target_dev = halfmap_dev;
    sector_t sector = bio->bi_iter.bi_sector;
    sector_t next_sector = sector;
    struct bio *split_bio = NULL;
    struct bio *current_bio = bio;
    struct halfmap_private* pri;
    // Split happend if bio size is more than 4k bytes
    for (int i = 0; i < bio_sectors(bio) - SECTORS_PER_PAGE; i += SECTORS_PER_PAGE) {  // 4K = 8 sectors
        uint16_t curr_phy_blk_map;
        if (sector >= ARRAY_SIZE(physical_block_map) || next_sector >= ARRAY_SIZE(physical_block_map)) {
            break;
        }
        curr_phy_blk_map = physical_block_map[sector];
        next_sector = next_sector + SECTORS_PER_PAGE;
        if (curr_phy_blk_map != physical_block_map[next_sector]) {
            split_bio = bio_split(current_bio, next_sector - sector, GFP_NOIO, &fs_bio_set);
            if (!split_bio) {
                return DM_MAPIO_KILL;
            }
             // Configurate phy_blk_addr
            pri = kmalloc(sizeof(halfmap_private), GFP_KERNEL);
            pri->phy_blk_addr = curr_phy_blk_map;
            current_bio->bi_private = pri;
            current_bio->bi_end_io = halfmap_end_io;

            bio_set_dev(current_bio, target_dev);
            update_block_usage(current_bio);
            submit_bio(current_bio);
            sector = next_sector;
        }
    }

    if (current_bio) {
        bio_set_dev(current_bio, target_dev);
        submit_bio(current_bio);
    }

    return DM_MAPIO_SUBMITTED;
}


static struct target_type halfmap_target = {
	.name   = "halfmap",
	.version = {1, 1, 0},
	.features = DM_TARGET_NOWAIT,
	.module = THIS_MODULE,
	.ctr    = halfmap_ctr,
	.map    = halfmap_map,
};

static int __init dm_halfmap_init(void)
{
    int r = 0;
    initialize_block_management();  // 블록 관리 시스템 초기화
	r = dm_register_target(&halfmap_target);

	if (r < 0)
		DMERR("register failed %d", r);

	return r;
}

static void __exit dm_halfmap_exit(void)
{
	dm_unregister_target(&halfmap_target);
}

module_init(dm_halfmap_init)
module_exit(dm_halfmap_exit)

MODULE_AUTHOR("Jana Saout <jana@saout.de>");
MODULE_DESCRIPTION(DM_NAME " dummy target returning halfmaps");
MODULE_LICENSE("GPL");
