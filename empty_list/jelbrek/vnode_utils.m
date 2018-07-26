//
//  *.c
//  async_wake_ios
//
//  Created by George on 18/12/17.
//  Copyright © 2017 Ian Beer. All rights reserved.
//

#include "kern_utils.h"
#include "patchfinder64.h"
#include "offsetof.h"
#include "../offsets.h"
#include "kexecute.h"

#include <stdlib.h>

extern uint64_t kslide;

int vnode_lookup(const char *path, int flags, uint64_t *vnode, uint64_t vfs_context) {
    
    size_t len = strlen(path) + 1;
    uint64_t ptr = kalloc(8);
    uint64_t ptr2 = kalloc(len);
    kwrite(ptr2, path, len);
    
    if (kexecute(ksym_vnode_lookup + kslide, ptr2, flags, ptr, vfs_context, 0, 0, 0)) {
        return -1;
    }
    *vnode = kread64(ptr);
    kfree(ptr2, len);
    kfree(ptr, 8);
    return 0;
}

uint64_t get_vfs_context() {
    return zm_fix_addr(kexecute(ksym_vfs_current_context + kslide, 1, 0, 0, 0, 0, 0, 0));
}

int vnode_put(uint64_t vnode) {
    return kexecute(ksym_vnode_put + kslide, vnode, 0, 0, 0, 0, 0, 0);
}

unsigned int init_offsets() {
    extern unsigned int getOffsets(uint64_t kslide);
    return getOffsets(kslide);
}
