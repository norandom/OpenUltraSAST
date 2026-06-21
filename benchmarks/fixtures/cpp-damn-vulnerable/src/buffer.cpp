// Memory-safety vulnerabilities modeled on Damn Vulnerable C/C++ Program.
#include <cstdio>
#include <cstdlib>
#include <cstring>

void copy_name(char *src) {
  char dst[16];
  strcpy(dst, src); // CWE-120 unbounded strcpy into fixed buffer
}

void greet(char *src) {
  char dst[16];
  strcat(dst, src); // CWE-120 unbounded strcat into fixed buffer
}

void read_line() {
  char buf[32];
  gets(buf); // CWE-120 gets has no bounds checking
}

void render(char *user) {
  char out[64];
  sprintf(out, "hello %s", user); // CWE-120 sprintf overflow
}

void copy_blob(char *dst, char *src, int len) {
  memcpy(dst, src, len); // CWE-120 memcpy with attacker length
}

void parse_int() {
  char name[8];
  scanf("%s", name); // CWE-120 unbounded scanf %s
}

char *grow(int len, int count) {
  // CWE-190 integer overflow in allocation size (no direct dangerous sink token)
  return (char *)malloc(len * count);
}
