#include "types.h"
#include "riscv.h"
#include "defs.h"
#include "param.h"
#include "memlayout.h"
#include "spinlock.h"
#include "proc.h"
#include "sleeplock.h"
#include "fs.h"
#include "file.h"

extern struct proc proc[];

uint64
sys_exit(void)
{
  int n;
  argint(0, &n);
  exit(n);
  return 0;  // not reached
}

uint64
sys_getpid(void)
{
  return myproc()->pid;
}

uint64
sys_fork(void)
{
  return fork();
}

uint64
sys_wait(void)
{
  uint64 p;
  argaddr(0, &p);
  return wait(p);
}

uint64
sys_sbrk(void)
{
  uint64 addr;
  int n;

  argint(0, &n);
  addr = myproc()->sz;
  if(growproc(n) < 0)
    return -1;
  return addr;
}

uint64
sys_sleep(void)
{
  int n;
  uint ticks0;

  argint(0, &n);
  if(n < 0)
    n = 0;
  acquire(&tickslock);
  ticks0 = ticks;
  while(ticks - ticks0 < n){
    if(killed(myproc())){
      release(&tickslock);
      return -1;
    }
    sleep(&ticks, &tickslock);
  }
  release(&tickslock);
  return 0;
}

uint64
sys_kill(void)
{
  int pid;

  argint(0, &pid);
  return kill(pid);
}

// return how many clock tick interrupts have occurred
// since start.
uint64
sys_uptime(void)
{
  uint xticks;

  acquire(&tickslock);
  xticks = ticks;
  release(&tickslock);
  return xticks;
}

uint64
sys_freemem(void)
{
  return kfreepages() * PGSIZE;
}

uint64
sys_procinfo(void)
{
  uint64 addr;
  struct proc *p;
  struct procinfo info;
  int n = 0;
  
  argaddr(0, &addr);
  
  for(p = proc; p < &proc[NPROC]; p++) {
    acquire(&p->lock);
    if(p->state != UNUSED) {
      info.pid = p->pid;
      info.ppid = p->parent ? p->parent->pid : 0;
      info.sz = p->sz;
      safestrcpy(info.name, p->name, sizeof(info.name));
      
      if(p->state == SLEEPING)
        safestrcpy(info.state, "SLEEPING", sizeof(info.state));
      else if(p->state == RUNNABLE)
        safestrcpy(info.state, "RUNNABLE", sizeof(info.state));
      else if(p->state == RUNNING)
        safestrcpy(info.state, "RUNNING", sizeof(info.state));
      else if(p->state == ZOMBIE)
        safestrcpy(info.state, "ZOMBIE", sizeof(info.state));
      else
        safestrcpy(info.state, "USED", sizeof(info.state));
      
      release(&p->lock);
      
      if(copyout(myproc()->pagetable, addr + n * sizeof(info), (char *)&info, sizeof(info)) < 0)
        return -1;
      n++;
    } else {
      release(&p->lock);
    }
  }
  
  return n;
}

uint64
sys_auditread(void)
{
  uint64 addr;
  int n;
  struct inode *ip;
  
  argaddr(0, &addr);
  argint(1, &n);
  
  begin_op();
  if((ip = namei("/audit.log")) == 0) {
    end_op();
    return -1;
  }
  ilock(ip);
  int r = readi(ip, 1, addr, 0, n < ip->size ? n : ip->size);
  iunlockput(ip);
  end_op();
  
  return r;
}
