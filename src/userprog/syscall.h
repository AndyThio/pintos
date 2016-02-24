#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);

//helper functions. TODO: move declaration to syscall.c
struct file *get_file(int fd);
#endif /* userprog/syscall.h */
