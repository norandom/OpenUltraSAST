// Command-execution and format-string vulnerabilities.
#include <cstdio>
#include <cstdlib>
#include <unistd.h>

void run_cmd(char *arg) {
  char cmd[256];
  strcpy(cmd, arg);
  system(cmd); // CWE-78 system runs attacker-controlled command
}

void read_pipe(char *arg) {
  FILE *fp = popen(arg, "r"); // CWE-78 popen runs attacker-controlled command
  if (fp) pclose(fp);
}

void launch(char *arg) {
  execlp("sh", "sh", "-c", arg, (char *)NULL); // CWE-78 execlp runs attacker input
}

void log_msg(char *user) {
  printf(user); // CWE-134 format string controlled by attacker
}
