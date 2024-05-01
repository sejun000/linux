/*
 * Copyright (C) 2003 Jana Saout <jana@saout.de>
 *
 * This file is released under the GPL.
 */

#include <linux/device-mapper.h>

#include <linux/module.h>
#include <linux/init.h>
#include <linux/bio.h>
#include <linux/types.h>
#include <linux/halfmap.h>
#include <asm/atomic.h>

#define SECTORS_PER_PAGE (8)
#define SSD_CAPACITY (32 * 1024 * 1024 * 1024ULL)
#define TOTAL_PHYSICAL_BLOCKS (8192)
#define PAGES_PER_BLOCK (1024)

#define DM_MSG_PREFIX "halfmap"
#define INVALID_MAP (0xFFFFFFFF)
static struct dm_dev* halfmap_dev;
#define ENTRY_SIZE (SSD_CAPACITY / 4096)
uint32_t physical_block_map[ENTRY_SIZE];

struct block_node {
    block_offset_t block_index;
    struct list_head list;
};

struct block_management {
    struct list_head free_blocks;
    struct list_head full_blocks;
    block_offset_t current_block_index;
    atomic_t write_count[TOTAL_PHYSICAL_BLOCKS];
    spinlock_t list_lock;
    spinlock_t allocator_lock;
};

static struct block_management blk_mgmt;


// 블록 관리 초기화
static void initialize_block_management(void) {
    block_offset_t i;
    INIT_LIST_HEAD(&blk_mgmt.free_blocks);
    INIT_LIST_HEAD(&blk_mgmt.full_blocks);
    for (i = 0; i < ENTRY_SIZE; i++) {
        physical_block_map[i] = INVALID_MAP;
    }
    for (i = 0; i < TOTAL_PHYSICAL_BLOCKS; i++) {
        struct block_node *node = kmalloc(sizeof(struct block_node), GFP_KERNEL);
        if (node) {
            node->block_index = i;
            list_add_tail(&node->list, &blk_mgmt.free_blocks);
        }
        blk_mgmt.write_count[i] = (atomic_t)ATOMIC_INIT(0);
        printk("halfmap init block mgmt %d\n", i);
    }
    blk_mgmt.current_block_index = 0;
    spin_lock_init(&blk_mgmt.list_lock);
    spin_lock_init(&blk_mgmt.allocator_lock);
}

static block_offset_t allocate_new_block(void) {
    spin_lock(&blk_mgmt.list_lock);
    if (!list_empty(&blk_mgmt.free_blocks)) {
        block_offset_t block_index;
        struct block_node *node = list_first_entry(&blk_mgmt.free_blocks, struct block_node, list);
        list_del(&node->list);
        block_index = node->block_index;
        spin_unlock(&blk_mgmt.list_lock);
        kfree(node);
        return block_index;
    }
    spin_unlock(&blk_mgmt.list_lock);
    return INVALID_MAP;
}

static void return_full_block(block_offset_t index) {
    struct block_node *node = kmalloc(sizeof(struct block_node), GFP_KERNEL);
    if (node) {
        node->block_index = index;
        spin_lock(&blk_mgmt.list_lock);
        list_add_tail(&node->list, &blk_mgmt.full_blocks);
        spin_unlock(&blk_mgmt.list_lock);
    }
}

// bio_end_io에서 호출될 블록 업데이트 함수
static block_offset_t update_block_usage(void) {
    block_offset_t block_index;
    int local_write_count;
    do {
        spin_lock(&blk_mgmt.allocator_lock);
        block_index = blk_mgmt.current_block_index;
        spin_unlock(&blk_mgmt.allocator_lock);
        printk("block offset %d %d\n", block_index, blk_mgmt.write_count[block_index]);
        local_write_count = atomic_add_return(1, &blk_mgmt.write_count[block_index]);
    } while (local_write_count > PAGES_PER_BLOCK);
    if (local_write_count == PAGES_PER_BLOCK) {
        block_offset_t new_block;
        return_full_block(block_index);
        new_block = allocate_new_block();
        if (new_block != INVALID_MAP) {
            spin_lock(&blk_mgmt.allocator_lock);
            blk_mgmt.current_block_index = new_block;
            spin_unlock(&blk_mgmt.allocator_lock);
        } else {
            printk(KERN_ERR "No free blocks available!\n");
            return INVALID_MAP;
        }
    }
    return block_index;
    
}

static int halfmap_ctr(struct dm_target *ti, unsigned int argc, char **argv)
{
    if (argc != 1) {
        ti->error = "Invalid argument count. Expected 1 arguments for a nvme device";
        return -EINVAL;
    }
    printk("halfmap_ctr init\n");
    if (dm_get_device(ti, argv[0], FMODE_READ | FMODE_WRITE, &halfmap_dev)) {
        ti->error = "Failed to open device";
        return -EINVAL;
    }
    printk("halfmap_ctr done\n");
    ti->num_discard_bios = 0;
    return 0;
}

// bio_end_io callback function definition
static void halfmap_end_io(struct bio *bio)
{
    struct halfmap_private* pri = bio->bi_private;
    printk("halfmap cmd done\n");
    if (bio_data_dir(bio) == WRITE) {
        if (pri == NULL) {
            printk("ERROR for halfmap read\n");
        }
        else {
            // mapping table update
            physical_block_map[bio->bi_iter.bi_sector / SECTORS_PER_PAGE] = pri->phy_blk_addr;
        }
        printk("halfmap write cmd done\n");
    }
    else {
        printk("halfmap read cmd done\n");
    }
    // free memory
    if (pri != NULL) {
        kfree(pri);
    }
    
}


/*
 * Return halfmaps only on reads
 */
static int halfmap_map(struct dm_target *ti, struct bio *bio)
{
    bool write = false;
    if (bio_data_dir(bio) == WRITE) {
        write = true;
        printk("halfmap write cmd\n");
    } else {
        printk("halfmap read cmd\n");
    }
    struct dm_dev *target_dev = halfmap_dev;
    sector_t sector = bio->bi_iter.bi_sector;
    sector_t next_sector = sector;
    struct bio *split_bio = NULL;
    struct bio *current_bio = bio;
    struct halfmap_private* pri;
    int i;
    // Split happend if bio size is more than 4k bytes
    for (i = 0; i < bio_sectors(bio) - SECTORS_PER_PAGE; i += SECTORS_PER_PAGE) {  // 4K = 8 sectors
        uint16_t curr_phy_blk_map;
        if (sector >= ARRAY_SIZE(physical_block_map) || next_sector >= ARRAY_SIZE(physical_block_map)) {
            break;
        }
        curr_phy_blk_map = physical_block_map[sector / SECTORS_PER_PAGE];
        next_sector = next_sector + SECTORS_PER_PAGE;
        printk("halfmap cmd sector %d next_sector %d curr_phy_blk_map %d physical_block_map %d\n", sector, next_sector, curr_phy_blk_map, physical_block_map);
        if (curr_phy_blk_map != physical_block_map[next_sector / SECTORS_PER_PAGE]) {
            block_offset_t allocated_block_index;
            printk("halfmap step 1\n");
            split_bio = bio_split(current_bio, next_sector - sector, GFP_NOIO, &fs_bio_set);
            if (!split_bio) {
                return DM_MAPIO_KILL;
            }
            printk("halfmap step 2\n");
             // Configurate phy_blk_addr
            pri = kmalloc(sizeof(struct halfmap_private), GFP_KERNEL);
            printk("halfmap step 3\n");
            if (write) {
                pri->old_phy_blk_addr = curr_phy_blk_map;
                allocated_block_index = update_block_usage();
                pri->phy_blk_addr = allocated_block_index;
            }
            else {
                printk("halfmap step 4\n");
                pri->phy_blk_addr = curr_phy_blk_map;
            }
            printk("halfmap step 5\n");
            split_bio->bi_private = pri;
            split_bio->bi_end_io = halfmap_end_io;
            printk("halfmap step 6\n");
            bio_set_dev(split_bio, target_dev->bdev);
            submit_bio(split_bio);
            sector = next_sector;
        }
    }

    if (current_bio) {
        uint16_t curr_phy_blk_map;
        block_offset_t allocated_block_index;
        curr_phy_blk_map = physical_block_map[sector / SECTORS_PER_PAGE];
        pri = kmalloc(sizeof(struct halfmap_private), GFP_KERNEL);
        if (write) {
            pri->old_phy_blk_addr = curr_phy_blk_map;
            allocated_block_index = update_block_usage();
            pri->phy_blk_addr = allocated_block_index;
        }
        else {
            pri->phy_blk_addr = curr_phy_blk_map;
        }
        current_bio->bi_private = pri;
        current_bio->bi_end_io = halfmap_end_io;
        bio_set_dev(current_bio, target_dev->bdev);
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
