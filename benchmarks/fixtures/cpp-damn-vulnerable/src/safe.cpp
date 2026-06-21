// Safe equivalents. None of these lines should produce a finding.
#include <cstdio>
#include <cstdlib>
#include <cstring>

void copy_name_safe(const char *src) {
  char dst[16];
  strncpy(dst, src, sizeof(dst) - 1); // bounded copy, not flagged
  dst[sizeof(dst) - 1] = '\0';
}

void render_safe(const char *user) {
  char out[64];
  snprintf(out, sizeof(out), "hello %s", user); // bounded, not flagged
}

void log_safe(const char *user) {
  printf("%s", user); // constant format string, not a format-string bug
}

size_t length_safe(const char *src) {
  return strnlen(src, 64); // bounded length, no dangerous sink
}
