#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "filesys/filesys.h"

static void syscall_handler (struct intr_frame *);
struct lock filelock;

void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(filelock);
}

static void
syscall_handler (struct intr_frame *f)
{
    unsigned callNum;
    int args[3];
    int numOfArgs;


    //##Get syscall number
    copy_in (&callNum, f->esp, sizeof callNum);

    //##Using the number find out which system call is being used
    //inumOfArgs = number of args that system call uses {0,1,2,3}
    //  W:aranged to be after call num (duh?)

    //copy_in (args, (uint32_t *) f->esp + 1, sizeof *args * numOfArgs);
    //  W: cant get very far without

    //##Use switch statement or something and run this below for each
    //##Depending on the callNum...

    //f->eax = desired_sys_call_fun (args[0], args[1], args[2]);
    //  W:so obvious...
    /
    switch(callnum){
        case SYS_EXIT:
            {
                numOfArgs = 1;
                copy_in (args, (uint32_t *) f->esp + 1, sizeof *args * numOfArgs);
                f->eax = exit(args[0]);
                break;
            }
        case SYS_WRITE:
             {
                numOfArgs = 3;
                copy_in (args, (uint32_t *) f->esp + 1, sizeof *args * numOfArgs);
                f -> eax = write(args[0], args[1], args[2]);
                break;
             }
    }
}

void exit (int status){
    struct thread * curr = current_thread();

    if (find_thread(curr -> parent_tid)){
        curr -> ct -> stat = status;
    }

    printf("%s: exit(%d) \n", curr -> name, status);
    thread_exit();

}

int write(int fd, const void*buffer, unsigned size){
    if (fd == STDOUT_FILENO){
        putbuf(buffer, size);
        return size;
    }

    //lock_aquire(filelock);
    //if (!fd)
    //lock_release(filelock);
    //  W:not quite done
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
      thread_exit ();
}




/* Creates a copy of user string US in kernel memory
   and returns it as a page that must be freed with
   palloc_free_page().
   Truncates the string at PGSIZE bytes in size.
   Call thread_exit() if any of the user accesses are invalid. */
static char *
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
