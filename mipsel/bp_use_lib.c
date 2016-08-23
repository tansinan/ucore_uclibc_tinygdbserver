/* Code sample: Use debuglib for setting breakpoints in a child process.
**
** Eli Bendersky (http://eli.thegreenplace.net)
** This code is in the public domain.
*/
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <syscall.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <sys/user.h>
#include <unistd.h>
#include <errno.h>

#include "gdb-server.h"
#include "debuglib.h"

int main(int argc, char** argv)
{
  pid_t child_pid;
  if (argc < 2) {
      fprintf(stderr, "Expected a program name as argument\n");
      return -1;
  }
  child_pid = fork();
  if (child_pid == 0)
      run_target(argv[1]);
  else if (child_pid > 0) ;
      ///run_debugger(child_pid);
  else {
      perror("fork");
      return -1;
  }
  //run_debugger(child_pid);
  wait(0);
  procmsg("child now at EIP = 0x%08x\n", get_child_eip(child_pid));
  printf("????\n");
  st_state_t st;
  st.listen_port = 1234;
  st.tracee_pid = child_pid;
  serve(&st);
  return 0;
}
