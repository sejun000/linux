#ifndef _HALFMAP_H
#define _HALFMAP_H 1

#include <linux/types.h>

typedef uint32_t block_offset_t;
struct halfmap_private {
    block_offset_t old_phy_blk_addr;
    block_offset_t phy_blk_addr;
};

#endif