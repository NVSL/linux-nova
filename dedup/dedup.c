#include<linux/kernel.h>
#include<linux/syscalls.h>
#include<linux/file.h>
#include<linux/fs.h>


int ksys_dedup(unsigned int fd){

	printk("1\n");
	struct fd f = fdget_pos(fd);
	printk("2\n");
	struct file *file = f.file;
	printk("3\n");
	file->f_op->dedup(1);
	return 0;
}


SYSCALL_DEFINE1(dedup, unsigned int, fd){
	printk("0\n");
	return ksys_dedup(fd);
}





