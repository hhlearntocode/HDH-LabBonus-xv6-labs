#include "kernel/types.h"
#include "user/user.h"

int
main(int argc, char *argv[])
{
  char *buf;
  int n;
  
  buf = malloc(4096);
  if(buf == 0) {
    printf("auditcat: malloc failed\n");
    exit(1);
  }
  
  n = auditread(buf, 4095);
  if(n < 0) {
    printf("auditcat: no audit log\n");
    free(buf);
    exit(1);
  }
  
  buf[n] = 0;
  printf("=== Audit Log ===\n%s", buf);
  
  free(buf);
  exit(0);
}
