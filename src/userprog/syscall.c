#include "userprog/syscall.h"
#include "userprog/process.h"
#include <stdio.h>
#include <stdbool.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/vaddr.h"
#include "devices/shutdown.h"

typedef int pid_t;

static void syscall_handler (struct intr_frame *);
struct lock filelock;


//syscall handler helper functions
static void copy_in (void *, const void *, size_t);
static char *copy_in_string (const char *);
static inline bool get_user (uint8_t *, const uint8_t *);
static bool verify_user (const void *);

//syscall functions
void halt(void);
void exit (int );
pid_t exec(const char* );
int wait(pid_t );
bool create (const char *, unsigned );
bool remove (const char *);
int open (const char *);
int filesize(int);
int write(int , const void *, unsigned );
int read(int , void *, unsigned );
void seek(int, unsigned);
unsigned tell(int );
void close(int fd);

//helper functions
struct file* get_file(int );

struct files{
    int fd;
    struct file *fil;
    struct list_elem filelem;
};

void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&filelock);
}

static void
syscall_handler (struct intr_frame *f)
{
    unsigned callNum;
    int args[3];
    int numOfArgs;

    //verify if esp is a valid pointer
    if(!verify_user(f->esp)){
        exit(-1);
    }

    //##Get syscall number
    copy_in (&callNum, f->esp, sizeof(callNum));

    //##Using the number find out which system call is being used
    //inumOfArgs = number of args that system call uses {0,1,2,3}
    //  W:aranged to be after call num (duh?)

    //copy_in (args, (uint32_t *) f->esp + 1, sizeof *args * numOfArgs);
    //  W: cant get very far without

    //##Use switch statement or something and run this below for each
    //##Depending on the callNum...

    //f->eax = desired_sys_call_fun (args[0], args[1], args[2]);
    //  W:so obvious...
    switch(callNum){
        // Halt the operating system
        case SYS_HALT:
            {
                numOfArgs = 0;
                halt();
                break;
            }
        // Terminate this process
        case SYS_EXIT:
            {
                numOfArgs = 1;
                copy_in (args, (uint32_t *) f->esp + 1, sizeof *args * numOfArgs);
                exit(args[0]);
                break;
            }
        // Start another process
        case SYS_EXEC:
            {
                numOfArgs = 1;
                copy_in (args, (uint32_t *) f->esp + 1, sizeof *args * numOfArgs);
                f->eax = exec((const char*) args[0]);
                break;
            }
        // Wait for a child process to die
        case SYS_WAIT:
            {
                numOfArgs = 1;
                copy_in (args, (uint32_t *) f->esp + 1, sizeof *args * numOfArgs);
                f->eax = wait(args[0]);
                break;
            }
        // Create a file
        case SYS_CREATE:
            {
                numOfArgs = 2;
                copy_in (args, (uint32_t *) f->esp + 1, sizeof *args * numOfArgs);
                f->eax = create((const char *) args[0], args[1]);
                break;
            }
        // Delete a file
        case SYS_REMOVE:
            {
                numOfArgs = 1;
                copy_in (args, (uint32_t *) f->esp + 1, sizeof *args * numOfArgs);
                f->eax = remove((const char *) args[0]);
                break;
            }
        // Open a file
        case SYS_OPEN:
            {
                numOfArgs = 1;
                copy_in (args, (uint32_t *) f->esp + 1, sizeof *args * numOfArgs);
                f->eax = open((const char *) args[0]);
                break;
            }
        // Obtain a file's size
        case SYS_FILESIZE:
            {
                numOfArgs = 1;
                copy_in (args, (uint32_t *) f->esp + 1, sizeof *args * numOfArgs);
                f->eax = filesize(args[0]);
                break;
            }
        // Read from a file
        case SYS_READ:
            {
                numOfArgs = 3;
                copy_in (args, (uint32_t*) f->esp + 1, sizeof *args * numOfArgs);
                f -> eax = read(args[0], (void *)args[1],(unsigned) args[2]);
                break;
            }
        // Write to a file
        case SYS_WRITE:
             {
                numOfArgs = 3;
                copy_in (args, (uint32_t *) f->esp + 1, sizeof *args * numOfArgs);
                f -> eax = write(args[0], (void *)args[1], (unsigned)args[2]);
                break;
             }
        //TODO: Change position in a file
        case SYS_SEEK:
            {
                numOfArgs = 2;
                copy_in (args, (uint32_t *) f->esp + 1, sizeof *args * numOfArgs);
                seek(args[0], (unsigned) args[1]);
                break;
            }
        //TODO: Report current position in a file
        case SYS_TELL:
            {
                numOfArgs = 1;
                copy_in (args, (uint32_t *) f->esp + 1, sizeof *args * numOfArgs);
                f -> eax = tell(args[0]);
                break;
            }
        //TODO: Close a file
        case SYS_CLOSE:
        {
                numOfArgs = 1;
                copy_in (args, (uint32_t *) f->esp + 1, sizeof *args * numOfArgs);
                close(args[0]);
                break;
        }
    }
}

void
halt (void){
    shutdown_power_off();
}

void
exit (int status){
    struct thread *curr = thread_current();

    if (find_thread(curr -> parent_tid)){
        curr -> ct -> stat = status;
    }

    while(!list_empty(&curr->files_list)){
        struct files *ftemp = list_entry(list_begin(&curr->files_list), struct files,
            filelem);
        list_pop_front(&curr->files_list);
        file_close(ftemp->fil);
        palloc_free_page(ftemp);
    }

    while(!list_empty(&curr->children)){
        struct child_ *ctemp = list_entry(list_begin(&curr->children), struct child_,
            childelem);
        list_pop_front(&curr->children);
        palloc_free_page(ctemp);
    }
    printf("%s: exit(%d)\n", curr -> name, status);
    thread_exit();

}

pid_t
exec (const char* cmd_line){
    if(verify_user(cmd_line)){
        int tid = process_execute(cmd_line);
        if(tid != TID_ERROR){
            return tid;
        }
        else{
            return -1;
        }
    }
    exit(-1);
    return -1;
}

int
wait(pid_t pid){
    return process_wait(pid);
}

bool
create(const char *file, unsigned initial_size){
    if(!verify_user(file)){
        exit(-1);
        return false;
    }
    lock_acquire(&filelock);
    bool ret = filesys_create(file, initial_size);
    lock_release(&filelock);
    return ret;
}

bool
remove(const char *file){
    lock_acquire(&filelock);
    bool ret = filesys_remove(file);
    lock_release(&filelock);
    return ret;
}

int
open(const char *file){
    if(!verify_user(file)){
        exit(-1);
        return -1;
    }
    struct files *newfile = palloc_get_page(0);
    newfile->fil = filesys_open(file);

    if(newfile->fil == NULL){
        return -1;
    }

    if(list_empty(&thread_current()->files_list)){
        newfile->fd = 2;
    }
    else{
        struct list_elem *e;
        int max_fd = 1;
        for(e = list_begin(&thread_current()->files_list);
              e!= list_end(&thread_current()->files_list);
              e = list_next(e)){
          struct files *temp= list_entry(e,struct files, filelem);
          if(temp->fd > max_fd){
              max_fd = temp->fd;
          }
        }

        newfile->fd = max_fd+1;

    }
    list_push_back(&thread_current()->files_list, &newfile->filelem);

    return newfile->fd;
}

int
filesize(int fd){
    struct file *temp = get_file(fd);
    if(temp == NULL){
        return -1;
    }
    return file_length(temp);
}

int
write(int fd, const void*buffer, unsigned size){
    if(!verify_user(buffer)){
        exit(-1);
        return -1;
    }
    if (fd == STDOUT_FILENO){
        putbuf(buffer, size);
        return size;
    }

    lock_acquire(&filelock);
    struct file *copyTo = get_file(fd);
    if (copyTo == NULL){
        lock_release(&filelock);
        return -1;
    }
    int ret = file_write(copyTo, buffer, size);
    lock_release(&filelock);
    return ret;
}

int
read(int fd, void *buffer, unsigned size){
    if(!verify_user(buffer)){
        exit(-1);
        return -1;
    }
    if (fd == STDIN_FILENO){
        uint8_t* buf_temp = (uint8_t *) buffer;
        int i;
        for(i = 0; i < size; ++i){
            buf_temp[i] = input_getc();
        }
        return size;
    }

    lock_acquire(&filelock);
    struct file *readFrom = get_file(fd);
    if(readFrom == NULL){
        lock_release(&filelock);
        return -1;
    }
    int ret = file_read(readFrom, buffer, size);
    lock_release(&filelock);
    return ret;
}

void
seek(int fd, unsigned position){
    struct file *temp = get_file(fd);
    if(temp == NULL){
        return;
    }
    file_seek(temp, (off_t) position);
}

unsigned
tell(int fd){
    struct file *temp = get_file(fd);
    if(temp == NULL){
        return -1;
    }
    return file_tell(temp);
}

void
close(int fd){
    struct thread *curr = thread_current();
    struct list_elem *e;
    for(e = list_begin(&curr->files_list);
            e != list_end(&curr->files_list); e = list_next(e)){
        struct files *temp = list_entry(e, struct files, filelem);
        if(temp->fd == fd){
            list_remove(&temp->filelem);
            file_close(temp->fil);
            palloc_free_page(temp);
            break;
        }
    }
}


/* Copies SIZE bytes from user address USRC to kernel address
   DST.
   Call thread_exit() if any of the user accesses are invalid. */
static void
copy_in (void *dst_, const void *usrc_, size_t size)
{
  uint8_t *dst = dst_;
  const uint8_t *usrc = usrc_;

  for (; size > 0; size--, dst++, usrc++)
    if (usrc >= (uint8_t *) PHYS_BASE || !get_user (dst, usrc))
        exit(-1);
}




/* Creates a copy of user string US in kernel memory
   and returns it as a page that must be freed with
copy_in_string (const char *us)
{
  char *ks;
  size_t length;

  ks = palloc_get_page (0);
  if (ks == NULL)
    thread_exit ();

  for (length = 0; length < PGSIZE; length++)
    {
      if (us >= (char *) PHYS_BASE || !get_user (ks + length, us++))
        {
          palloc_free_page (ks);
          thread_exit ();
        }

      if (ks[length] == '\0')
        return ks;
    }
  ks[PGSIZE - 1] = '\0';
  return ks;
}


/* Copies a byte from user address USRC to kernel address DST.
   USRC must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
static inline bool
get_user (uint8_t *dst, const uint8_t *usrc)
{
  int eax;
  asm ("movl $1f, %%eax; movb %2, %%al; movb %%al, %0; 1:"
       : "=m" (*dst), "=&a" (eax) : "m" (*usrc));
  return eax != 0;
}




/* Returns true if UADDR is a valid, mapped user address,
   false otherwise. */
static bool
verify_user (const void *uaddr)
{
  return (uaddr < PHYS_BASE
          && pagedir_get_page (thread_current ()->pagedir, uaddr) != NULL);
}

struct file*
get_file(int fd){
    struct thread *curr = thread_current();
    struct list_elem *e;
    for(e = list_begin(&curr->files_list);
            e != list_end(&curr->files_list); e = list_next(e)){
        struct files *temp = list_entry(e, struct files, filelem);
        if(temp->fd == fd){
            return temp->fil;
        }
    }
    return NULL;
}
