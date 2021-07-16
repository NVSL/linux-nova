#include<linux/kernel.h>
#include<linux/syscalls.h>

SYSCALL_DEFINE0(dedup){
	printk("dedupping\n");
	return 0;
}
