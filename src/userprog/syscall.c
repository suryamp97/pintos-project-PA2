#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/exception.h"
#include "filesys/filesys.h"
#include "devices/shutdown.h"


static void syscall_handler (struct intr_frame *);
void check_valid(void*);
void exit(int status);
int write(int fd,void *buffer, unsigned size);
int read(int fd,void *buffer, unsigned size);
bool remove(char *file);
bool create (char *file, unsigned initial_size);


void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");

}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{

   //hex_dump(f->esp,f->esp,200,1);

    check_valid(f->esp);
    int sys_call = *(int*)(f->esp);
    if(sys_call == 1) //exit
    {
	check_valid(f->esp+4);
	exit(*(int *)(f->esp+4));
    }

   if(sys_call == 2){ //wait
	check_valid(f->esp+4);
	f->eax = process_wait(*(int *)(f->esp+4));      
	} 

if(sys_call == 6)
{	
check_valid(*(int *)(f->esp+4));
	if(*(int *)(f->esp+4) == "")
	{ f->eax= (int)-1;} 
//f->eax= open(*(int *)(f->esp+4));
}
  if(sys_call == 9) //write
    {
	check_valid(f->esp+4);
	check_valid(f->esp+8);
	check_valid(*(int *)(f->esp+8));
	check_valid(f->esp+12); 
        f->eax = write(*(int *)(f->esp+4),*(int *)(f->esp+8),*(unsigned *)(f->esp+12));
    }
  if(sys_call == 8) //read
    {
	check_valid(f->esp+4);
	check_valid(f->esp+8);
	check_valid(*(int *)(f->esp+8));
	check_valid(f->esp+12); 
        f->eax = read(*(int *)(f->esp+4),*(int *)(f->esp+8),*(unsigned *)(f->esp+12));
    }
   if(sys_call == 0){ //halt
	 shutdown_power_off();        
	}  

   if(sys_call == 5){ //remove
            check_valid(f->esp+4);
            f->eax = remove(*(int *)(f->esp+4));
               
	} 
   if(sys_call == 4){ //create
	    check_valid(f->esp+16);
            check_valid(f->esp+20);
            check_valid(*(int *)(f->esp+16));
            f->eax = create(*(int *)(f->esp+16),*(unsigned *)(f->esp+20));
	}
   
}

int read(int fd, void *buffer, unsigned size){

    if(fd == STDIN_FILENO){
        uint8_t * buffer_ = (uint8_t *) buffer;
        for(int i = 0; i < size; i++)
            {buffer_[i] = input_getc();}

        return size;
    	}
	else
	{return size;}
}

int write(int fd,void *buffer, unsigned size)
{
 if(fd == STDOUT_FILENO){
	putbuf(buffer, size);
	return size;
	}
}


bool create (char *file, unsigned initial_size){
    return filesys_create(file, initial_size);
}

bool remove(char *file){
    return filesys_remove(file);
}

void exit(int status)
{
        printf ("%s: exit(%d)\n", thread_current()->name, status);
        thread_exit();
}
void check_valid(void *addr)
{
	if(addr==NULL){
		exit(-1);
		}
	if(addr>=PHYS_BASE)
	{
		exit(-1);
		}
	if(!pagedir_get_page(thread_current()->pagedir, addr))
	{
		exit(-1);
		}

}

