#include <cstdlib>
#include <cstring>

void copy_user(char *dst, char *src) { memcpy(dst, src, 128); }

void run_user(char *arg) {
  char cmd[256];
  std::strcpy(cmd, arg);
  system(cmd);
}
