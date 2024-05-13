#include "userprog/syscall.h"
#include <stdio.h>
#include <stdlib.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
// #include "lib/user/syscall.h"
#include "filesys/filesys.h"
#include "threads/synch.h"

struct file_elem {
    int fd;
    struct list_elem elem;
};

struct lock files_lock;

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");

  lock_init(&files_lock);
}

struct file_elem* get_file(struct list* files_opened, int fd) {
    for (struct list_elem* e = list_begin(files_opened); e != list_end(files_opened); e = list_next(e)) {
        struct file_elem* cur_file = list_entry(e, struct file_elem, elem);
        if (cur_file->fd == fd)
            return cur_file;
    }
    return NULL;
}

void insert_file(struct list* files_opened, int fd) {
    struct file_elem* cur_file = (struct file_elem*) malloc(sizeof(struct file_elem));
    cur_file->fd = fd;

    list_push_back(files_opened, &(cur_file->elem));
}

void remove_file(struct list* files_opened, int fd) {
    for (struct list_elem* e = list_begin(files_opened); e != list_end(files_opened); e = list_next(e)) {
        struct file_elem* cur_file = list_entry(e, struct file_elem, elem);
        if (cur_file->fd == fd) {
            list_remove(e);
            free(cur_file);
            return;
        }
    }
}

void handle_create(struct intr_frame *f) {
    f->esp += 4;
    const char* file = *(const char **)(f->esp);
    f->esp += 4;
    unsigned initial_size = *(unsigned*)(f->esp);

    lock_acquire(&files_lock);
    f->eax = (uint32_t) create(file, initial_size);
    lock_release(&files_lock);
}

void handle_remove(struct intr_frame *f) {
    f->esp += 4;
    const char* file = *(const char **)(f->esp);

    lock_acquire(&files_lock);
    f->eax = (uint32_t) remove(file);
    lock_release(&files_lock);
}

void handle_open(struct intr_frame *f) {
    f->esp += 4;
    const char* file = *(const char **)(f->esp);

    lock_acquire(&files_lock);
    uint32_t res = (uint32_t) open(file);
    lock_release(&files_lock);

    f->eax = res;
    if (res != -1)
        insert_file(&(thread_current()->files_opened), res);
}

void handle_filesize(struct intr_frame *f) {
    f->esp += 4;
    int fd = *(int*)(f->esp);

    lock_acquire(&files_lock);
    f->eax = (uint32_t) filesize(fd);
    lock_release(&files_lock);
}

void handle_read(struct intr_frame *f) {
    f->esp += 4;
    int fd = *(int*)(f->esp);
    f->esp += 4;
    void* buffer = *(void **)(f->esp);
    f->esp += 4;
    unsigned length = *(unsigned*)(f->esp);

    lock_acquire(&files_lock);
    f->eax = (uint32_t) read(fd, buffer, length);
    lock_release(&files_lock);
}

void handle_write(struct intr_frame *f) {
    f->esp += 4;
    int fd = *(int*)(f->esp);
    f->esp += 4;
    const void* buffer = *(const void **)(f->esp);
    f->esp += 4;
    unsigned length = *(unsigned*)(f->esp);

    lock_acquire(&files_lock);
    f->eax = (uint32_t) write(fd, buffer, length);
    lock_release(&files_lock);
}

void handle_seek(struct intr_frame *f) {
    f->esp += 4;
    int fd = *(int*)(f->esp);
    f->esp += 4;
    unsigned position = *(unsigned*)(f->esp);

    lock_acquire(&files_lock);
    seek(fd, position);
    lock_release(&files_lock);
}

void handle_tell(struct intr_frame *f) {
    f->esp += 4;
    int fd = *(int*)(f->esp);

    lock_acquire(&files_lock);
    f->eax = (uint32_t) tell(fd);
    lock_release(&files_lock);
}

void handle_close(struct intr_frame *f) {
    f->esp += 4;
    int fd = *(int*)(f->esp);

    lock_acquire(&files_lock);
    close(fd);
    lock_release(&files_lock);

    remove_file(&(thread_current()->files_opened), fd);
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  int sysCallType = (int)f->esp;
  if (sysCallType == SYS_CREATE) {
    handle_create(f);
  } else if (sysCallType == SYS_REMOVE) {
    handle_remove(f);
  } else if (sysCallType == SYS_OPEN) {
    handle_open(f);
  } else if (sysCallType == SYS_FILESIZE) {
    handle_filesize(f);
  } else if (sysCallType == SYS_READ) {
    handle_read(f);
  } else if (sysCallType == SYS_WRITE) {
    handle_write(f);
  } else if (sysCallType == SYS_SEEK) {
    handle_seek(f);
  } else if (sysCallType == SYS_TELL) {
    handle_tell(f);
  } else if (sysCallType == SYS_CLOSE) {
    handle_close(f);
  }
  
  thread_exit ();
}
