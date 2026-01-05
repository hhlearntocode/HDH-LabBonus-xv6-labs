#include "kernel/types.h"
#include "user/user.h"

int
main(int argc, char *argv[])
{
  char buf[4096];
  int n;
  
  n = auditread(buf, sizeof(buf) - 1);
  if(n < 0) {
    printf("auditcat: no audit log\n");
    exit(1);
  }
  
  buf[n] = 0;
  printf("=== Audit Log ===\n%s", buf);
  
  exit(0);
}
