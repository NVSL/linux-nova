#ifndef __TIERING_H
#define __TIERING_H

#include "nova.h"

int  nova_init_tiering(unsigned long);
int  nova_setup_tiering(struct nova_sb_info *sbi);
void nova_cleanup_tiering(void);
void nova_reset_tiering(void);
void nova_persist_page_cache(void);

#endif // __TIERING_H
