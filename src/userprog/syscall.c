#include "userprog/syscall.h"
#include <stdio.h>
#include <stdlib.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "filesys/filesys.h"
#include "filesys/file.h"

struct file_elem {
    int fd;
    struct list_elem elem;
};

struct lock files_lock;

static void syscall_handler (struct intr_frame *);
// static struct lock files_sync_lock;
int get_int(int** esp);
char* get_char_ptr(char*** esp);
void get_void_ptr(void*** esp);
void validate_void_ptr(const void* ptr);

void handle_halt();
int handle_exec();
int handle_wait();
void handle_exit();

void handle_create(struct intr_frame *f);
void handle_remove(struct intr_frame *f);
void handle_open(struct intr_frame *f);
void handle_filesize(struct intr_frame *f);
void handle_read(struct intr_frame *f);
void handle_write(struct intr_frame *f);
void handle_seek(struct intr_frame *f);
void handle_tell(struct intr_frame *f);
void handle_close(struct intr_frame *f);





void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  
  lock_init(&files_lock);
}


struct open_file* get_file(struct list* open_files, int fd) {
    for (struct list_elem* e = list_begin(open_files); e != list_end(open_files); e = list_next(e)) {
        struct open_file* cur_file = list_entry(e, struct open_file, elem);
        if (cur_file->fd == fd)
            return cur_file;
    }
    return NULL;
}

void insert_file(struct list* files_opened, int fd) {
    struct open_file* cur_file = (struct open_file*) malloc(sizeof(struct open_file));
    cur_file->fd = fd;
    // cur_file->ptr;

    list_push_back(files_opened, &(cur_file->elem));
}

void remove_file(struct list* files_opened, int fd) {
    for (struct list_elem* e = list_begin(files_opened); e != list_end(files_opened); e = list_next(e)) {
        struct open_file* cur_file = list_entry(e, struct open_file, elem);
        if (cur_file->fd == fd) {
            list_remove(e);
            free(cur_file);
            return;
        }
    }
}


static void
syscall_handler (struct intr_frame *f) 
{
  // printf ("system call!\n");
  validate_void_ptr(f->esp); // check that the address of the system call is valid

  int syscall = *  (int*)(f->esp); // get the system call number

  if(syscall == SYS_HALT)
  {
    handle_halt();
  } 
  else if(syscall == SYS_EXIT) // contains status
  {
    validate_void_ptr(f->esp +  4); // check that the address of the status variable is valid
    int status = *  (int*)(f->esp + 4); // get the status variable
    handle_exit(status); // call the exit function with the status variable
  }
  else if(syscall == SYS_EXEC) // contains cmd_line (char*)
  {
    validate_void_ptr(f->esp +  4); // check that the address of the character pointer is valid
    char* cmd_line = *  (char**)(f->esp + 4); // get the character pointer itself
    validate_void_ptr(cmd_line); // check that the address of the character pointer is valid
    f->eax = handle_exec(cmd_line); // call the exec function with the character pointer and store the return value in eax register
  }
  else if(syscall == SYS_WAIT)
  {
    validate_void_ptr(f->esp +  4); // check that the address of the pid variable is valid
    int pid = *  (int*)(f->esp + 4); // get the pid variable
    f->eax = handle_wait(pid); // call the wait function with the pid variable and store the return value in eax register
  }
  else if(syscall == SYS_CREATE)
  {
    validate_void_ptr(f->esp +  4); // check that the address of the file name is valid
    validate_void_ptr(f->esp +  8); // check that the address of the initial size is valid
    handle_create(f);
  }
  else if(syscall == SYS_REMOVE)
  {
    validate_void_ptr(f->esp +  4); // check that the address of the file name is valid
    handle_remove(f);
  }
  else if(syscall == SYS_OPEN)
  {
    validate_void_ptr(f->esp +  4); // check that the address of the file name is valid
    handle_open(f);
  }
  else if(syscall == SYS_FILESIZE)
  {
    validate_void_ptr(f->esp +  4); // check that the address of the file descriptor is valid
    handle_filesize(f);
  }
  else if(syscall == SYS_READ)
  {
    validate_void_ptr(f->esp +  4); // check that the address of the file descriptor is valid
    validate_void_ptr(f->esp +  8); // check that the address of the buffer is valid
    validate_void_ptr(f->esp +  12); // check that the address of the length is valid
    handle_read(f);
  }
  else if(syscall == SYS_WRITE)
  {
    validate_void_ptr(f->esp +  4); // check that the address of the file descriptor is valid
    validate_void_ptr(f->esp +  8); // check that the address of the buffer is valid
    validate_void_ptr(f->esp +  12); // check that the address of the length is valid
    handle_write(f);
  }
  else if(syscall == SYS_SEEK)
  {
    validate_void_ptr(f->esp +  4); // check that the address of the file descriptor is valid
    validate_void_ptr(f->esp +  8); // check that the address of the position is valid
    handle_seek(f);
  }
  else if(syscall == SYS_TELL)
  {
    validate_void_ptr(f->esp +  4); // check that the address of the file descriptor is valid
    handle_tell(f);
  }
  else if(syscall == SYS_CLOSE)
  {
    validate_void_ptr(f->esp +  4); // check that the address of the file descriptor is valid
    handle_close(f);
  }
  thread_exit ();
}



void handle_halt()
{
  shutdown_power_off();
}

int handle_exec(char* cmd_line)
{
  return process_execute(cmd_line);
}

int handle_wait(int pid)
{
  return process_wait(pid);
}




void validate_void_ptr(const void* ptr)
{
  if(ptr == NULL // if the user used a null pointer
    || !is_user_vaddr(ptr)  // if the user used an invalid address(it must be in the user space)
    || pagedir_get_page(thread_current()->pagedir, ptr) == NULL // if the user used an address that is not mapped to a page
  ) {
    handle_exit(-1); // exit with status -1
  }


}

void handle_exit(int status)
{
  // exit  handling //
  thread_current()->status = status;
  process_exit();
}
void handle_create(struct intr_frame *f)
{
    f->esp += 4;
    const char* file = *(const char **)(f->esp);
    f->esp += 4;
    unsigned initial_size = *(unsigned*)(f->esp);

    lock_acquire(&files_lock);
    f->eax = (uint32_t) filesys_create(file, initial_size);
    lock_release(&files_lock);
}
void handle_remove(struct intr_frame *f)
{
    f->esp += 4;
    const char* file = *(const char **)(f->esp);

    lock_acquire(&files_lock);
    f->eax = (uint32_t) filesys_remove(file);
    lock_release(&files_lock);
}
void handle_open(struct intr_frame *f)
{
    static unsigned long global_fd = 2;

    f->esp += 4;
    const char* file = *(const char **)(f->esp);

    lock_acquire(&files_lock);
    struct file* cur_file = filesys_open(file);
    lock_release(&files_lock);

    if (file != NULL) {
        struct open_file* new_file = (struct open_file*) malloc(sizeof(struct open_file));
        new_file->fd = global_fd;
        new_file->ptr = cur_file;

        lock_acquire(&files_lock);
        global_fd++;
        lock_release(&files_lock);

        struct list_elem* e = &(new_file->elem);
        list_push_back(&thread_current()->open_files, e);

        f->eax = new_file->fd;
    }
}
void handle_filesize(struct intr_frame *f)
{
    f->esp += 4;
    int fd = *(int*)(f->esp);

    lock_acquire(&files_lock);
    f->eax = (uint32_t) file_length(fd);
    lock_release(&files_lock);
}
void handle_read(struct intr_frame *f)
{
    f->esp += 4;
    int fd = *(int*)(f->esp);
    f->esp += 4;
    void* buffer = *(void **)(f->esp);
    f->esp += 4;
    unsigned length = *(unsigned*)(f->esp);

    struct open_file* cur_file = get_file(&thread_current()->open_files, fd);

    lock_acquire(&files_lock);
    f->eax = (uint32_t) file_read(cur_file->ptr, buffer, length);
    lock_release(&files_lock);
}
void handle_write(struct intr_frame *f)
{
    f->esp += 4;
    int fd = *(int*)(f->esp);
    f->esp += 4;
    const void* buffer = *(const void **)(f->esp);
    f->esp += 4;
    unsigned length = *(unsigned*)(f->esp);

    struct open_file* cur_file = get_file(&thread_current()->open_files, fd);

    lock_acquire(&files_lock);
    f->eax = (uint32_t) file_write(cur_file->ptr, buffer, length);
    lock_release(&files_lock);
}
void handle_seek(struct intr_frame *f)
{
    f->esp += 4;
    int fd = *(int*)(f->esp);
    f->esp += 4;
    unsigned position = *(unsigned*)(f->esp);

    lock_acquire(&files_lock);
    file_seek(fd, position);
    lock_release(&files_lock);
}
void handle_tell(struct intr_frame *f)
{
    f->esp += 4;
    int fd = *(int*)(f->esp);

    lock_acquire(&files_lock);
    f->eax = (uint32_t) file_tell(fd);
    lock_release(&files_lock);
}
void handle_close(struct intr_frame *f)
{
    f->esp += 4;
    int fd = *(int*)(f->esp);
    struct open_file* cur_file = get_file(&(thread_current()->open_files), fd);

    lock_acquire(&files_lock);
    file_close(cur_file->ptr);
    lock_release(&files_lock);

    list_remove(&cur_file->elem);
}


