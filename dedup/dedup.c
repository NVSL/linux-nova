#include<linux/kernel.h>
#include<linux/syscalls.h>
#include<linux/file.h>
#include<linux/fs.h>

int real_dedup(struct file *file){
	if(file->f_op->dedup)
		return file->f_op->dedup(1);
	return 0;
}

int ksys_dedup(unsigned int fd){
	struct fd f = fdget_pos(fd);
	if(f.file){
		return real_dedup(f.file);
	}
	return 0;
}


SYSCALL_DEFINE1(dedup, unsigned int, fd){
  return ksys_dedup(fd);
}
