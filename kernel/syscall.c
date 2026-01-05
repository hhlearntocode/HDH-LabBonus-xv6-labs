#include "types.h"
#include "param.h"
#include "memlayout.h"
#include "riscv.h"
#include "spinlock.h"
#include "proc.h"
#include "syscall.h"
#include "defs.h"
#include "sleeplock.h"
#include "fs.h"
#include "file.h"
#include "stat.h"

char *syscall_names[] = {
[SYS_fork]    "fork",
[SYS_exit]    "exit",
[SYS_wait]    "wait",
[SYS_pipe]    "pipe",
[SYS_read]    "read",
[SYS_kill]    "kill",
[SYS_exec]    "exec",
[SYS_fstat]   "fstat",
[SYS_chdir]   "chdir",
[SYS_dup]     "dup",
[SYS_getpid]  "getpid",
[SYS_sbrk]    "sbrk",
[SYS_sleep]   "sleep",
[SYS_uptime]  "uptime",
[SYS_open]    "open",
[SYS_write]   "write",
[SYS_mknod]   "mknod",
[SYS_unlink]  "unlink",
[SYS_link]    "link",
[SYS_mkdir]   "mkdir",
[SYS_close]   "close",
[SYS_freemem] "freemem",
[SYS_procinfo] "procinfo",
[SYS_auditread] "auditread",
};

void
auditlog(int pid, int syscall_num)
{
  struct inode *ip, *dp;
  char buf[128];
  char name[DIRSIZ];
  int n, i;
  
  begin_op();
  
  dp = nameiparent("/audit.log", name);
  if(dp == 0) {
    end_op();
    return;
  }
  
  ilock(dp);
  
  if((ip = dirlookup(dp, name, 0)) == 0){
    if((ip = ialloc(dp->dev, T_FILE)) == 0){
      iunlockput(dp);
      end_op();
      return;
    }
    
    ilock(ip);
    ip->major = 0;
    ip->minor = 0;
    ip->nlink = 1;
    iupdate(ip);
    
    if(dirlink(dp, name, ip->inum) < 0){
      iunlockput(ip);
      iunlockput(dp);
      end_op();
      return;
    }
    iunlockput(dp);
  } else {
    iunlockput(dp);
    ilock(ip);
  }
  
  buf[0] = 'P';
  buf[1] = 'I';
  buf[2] = 'D';
  buf[3] = ':';
  i = 4;
  if(pid >= 100) buf[i++] = '0' + (pid / 100) % 10;
  if(pid >= 10) buf[i++] = '0' + (pid / 10) % 10;
  buf[i++] = '0' + (pid % 10);
  buf[i++] = ' ';
  buf[i++] = 'S';
  buf[i++] = 'Y';
  buf[i++] = 'S';
  buf[i++] = 'C';
  buf[i++] = 'A';
  buf[i++] = 'L';
  buf[i++] = 'L';
  buf[i++] = ':';
  for(n = 0; syscall_names[syscall_num][n]; n++)
    buf[i++] = syscall_names[syscall_num][n];
  buf[i++] = '\n';
  n = i;
  
  writei(ip, 0, (uint64)buf, ip->size, n);
  iupdate(ip);
  
  iunlockput(ip);
  end_op();
}

// Fetch the uint64 at addr from the current process.
int
fetchaddr(uint64 addr, uint64 *ip)
{
  struct proc *p = myproc();
  if(addr >= p->sz || addr+sizeof(uint64) > p->sz) // both tests needed, in case of overflow
    return -1;
  if(copyin(p->pagetable, (char *)ip, addr, sizeof(*ip)) != 0)
    return -1;
  return 0;
}

// Fetch the nul-terminated string at addr from the current process.
// Returns length of string, not including nul, or -1 for error.
int
fetchstr(uint64 addr, char *buf, int max)
{
  struct proc *p = myproc();
  if(copyinstr(p->pagetable, buf, addr, max) < 0)
    return -1;
  return strlen(buf);
}

static uint64
argraw(int n)
{
  struct proc *p = myproc();
  switch (n) {
  case 0:
    return p->trapframe->a0;
  case 1:
    return p->trapframe->a1;
  case 2:
    return p->trapframe->a2;
  case 3:
    return p->trapframe->a3;
  case 4:
    return p->trapframe->a4;
  case 5:
    return p->trapframe->a5;
  }
  panic("argraw");
  return -1;
}

// Fetch the nth 32-bit system call argument.
void
argint(int n, int *ip)
{
  *ip = argraw(n);
}

// Retrieve an argument as a pointer.
// Doesn't check for legality, since
// copyin/copyout will do that.
void
argaddr(int n, uint64 *ip)
{
  *ip = argraw(n);
}

// Fetch the nth word-sized system call argument as a null-terminated string.
// Copies into buf, at most max.
// Returns string length if OK (including nul), -1 if error.
int
argstr(int n, char *buf, int max)
{
  uint64 addr;
  argaddr(n, &addr);
  return fetchstr(addr, buf, max);
}

// Prototypes for the functions that handle system calls.
extern uint64 sys_fork(void);
extern uint64 sys_exit(void);
extern uint64 sys_wait(void);
extern uint64 sys_pipe(void);
extern uint64 sys_read(void);
extern uint64 sys_kill(void);
extern uint64 sys_exec(void);
extern uint64 sys_fstat(void);
extern uint64 sys_chdir(void);
extern uint64 sys_dup(void);
extern uint64 sys_getpid(void);
extern uint64 sys_sbrk(void);
extern uint64 sys_sleep(void);
extern uint64 sys_uptime(void);
extern uint64 sys_open(void);
extern uint64 sys_write(void);
extern uint64 sys_mknod(void);
extern uint64 sys_unlink(void);
extern uint64 sys_link(void);
extern uint64 sys_mkdir(void);
extern uint64 sys_close(void);
extern uint64 sys_freemem(void);
extern uint64 sys_procinfo(void);
extern uint64 sys_auditread(void);

// An array mapping syscall numbers from syscall.h
// to the function that handles the system call.
static uint64 (*syscalls[])(void) = {
[SYS_fork]    sys_fork,
[SYS_exit]    sys_exit,
[SYS_wait]    sys_wait,
[SYS_pipe]    sys_pipe,
[SYS_read]    sys_read,
[SYS_kill]    sys_kill,
[SYS_exec]    sys_exec,
[SYS_fstat]   sys_fstat,
[SYS_chdir]   sys_chdir,
[SYS_dup]     sys_dup,
[SYS_getpid]  sys_getpid,
[SYS_sbrk]    sys_sbrk,
[SYS_sleep]   sys_sleep,
[SYS_uptime]  sys_uptime,
[SYS_open]    sys_open,
[SYS_write]   sys_write,
[SYS_mknod]   sys_mknod,
[SYS_unlink]  sys_unlink,
[SYS_link]    sys_link,
[SYS_mkdir]   sys_mkdir,
[SYS_close]   sys_close,
[SYS_freemem] sys_freemem,
[SYS_procinfo] sys_procinfo,
[SYS_auditread] sys_auditread,
};

void
syscall(void)
{
  int num;
  struct proc *p = myproc();

  num = p->trapframe->a7;
  if(num > 0 && num < NELEM(syscalls) && syscalls[num]) {
    if(num != SYS_auditread)
      auditlog(p->pid, num);
    p->trapframe->a0 = syscalls[num]();
  } else {
    printf("%d %s: unknown sys call %d\n",
            p->pid, p->name, num);
    p->trapframe->a0 = -1;
  }
}
