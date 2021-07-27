#include<linux/kernel.h>
#include<linux/syscalls.h>
#include<linux/file.h>
#include<linux/fs.h>

int real_dedup(struct file *file){
	printk("dedup system call\n");
	if(file->f_op->dedup){
		return file->f_op->dedup(file);
	}
	return 0;
}

int ksys_dedup(void){
	int ret = 0;
	struct file *filp=NULL;
	
	filp = filp_open("/mnt/nova/deduptable",O_APPEND|O_RDWR|O_CREAT,0);
	if(filp){
		ret = real_dedup(filp);
	}
	filp_close(filp,NULL);
	return ret;
}


SYSCALL_DEFINE0(dedup){
  return ksys_dedup();
}
