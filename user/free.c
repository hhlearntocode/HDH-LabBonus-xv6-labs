#include "kernel/types.h"
#include "user/user.h"

int
main(int argc, char *argv[])
{
  int freebytes = freemem();
  int total = 128 * 1024 * 1024;
  int used = total - freebytes;
  
  printf("Memory Status:\n");
  printf("Total:  %d KB (%d MB)\n", total / 1024, total / 1024 / 1024);
  printf("Used:   %d KB (%d MB)\n", used / 1024, used / 1024 / 1024);
  printf("Free:   %d KB (%d MB)\n", freebytes / 1024, freebytes / 1024 / 1024);
  
  exit(0);
}
