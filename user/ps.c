#include "kernel/types.h"
#include "kernel/param.h"
#include "user/user.h"

int
main(int argc, char *argv[])
{
  struct procinfo info[NPROC];
  int n = procinfo(info);
  
  printf("PID\tPPID\tSTATE\t\tSIZE\tNAME\n");
  for(int i = 0; i < n; i++) {
    printf("%d\t%d\t%s\t\t%d\t%s\n", 
           info[i].pid, 
           info[i].ppid, 
           info[i].state, 
           info[i].sz,
           info[i].name);
  }
  
  exit(0);
}
