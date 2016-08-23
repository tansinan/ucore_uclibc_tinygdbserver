/* Code sample: simplistic "library" of debugging tools.
**
** Eli Bendersky (http://eli.thegreenplace.net)
** This code is in the public domain.
*/
#include <stdio.h>
#include <assert.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/types.h>

#include <sys/user.h>
#include <unistd.h>
#include <errno.h>

#include "debuglib.h"


/* Print a message to stdout, prefixed by the process ID
*/
void procmsg(const char* format, ...)
{
    va_list ap;
    fprintf(stdout, "[%d] ", getpid());
    va_start(ap, format);
    vfprintf(stdout, format, ap);
    va_end(ap);
}


/* Run a target process in tracing mode by exec()-ing the given program name.
*/
void run_target(const char* programname)
{
    procmsg("target started. will run '%s'\n", programname);

    /* Allow tracing of this process */
    if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) {
        perror("ptrace");
        return;
    }

    /* Replace this process's image with the given program */
    execl(programname, programname, 0);
}


void dbglib_get_child_registers(struct user_regs_struct *regs, pid_t pid)
{
  ptrace(PTRACE_GETREGS, pid, 0, regs);
}

void dbglib_set_child_registers(struct user_regs_struct *regs, pid_t pid)
{
  ptrace(PTRACE_SETREGS, pid, 0, regs);
}

int dbglib_get_child_register_count(struct user_regs_struct *regs)
{
  return 38; //AMD64
}

uintptr_t dbglib_get_child_register_by_gdb_index(struct user_regs_struct *regs, int i, int* bitwidth)
{
  *bitwidth = 32;
  if(i < 32) {
    return regs->regs[i];
  }
  switch(i) {
    case 32: return regs->status;
    case 33: return regs->lo;
    case 34: return regs->hi;
    case 35: return regs->badvaddr;
    case 36: return regs->cause;
    case 37: return regs->epc;
  }
  return 0;
}


void dbglib_set_child_register_by_gdb_index(struct user_regs_struct *regs, int i, uintptr_t value)
{
  if(i < 32) {
    regs->regs[i] = value;
    return;
  }
  switch(i) {
    case 32: regs->status = value;break;
    case 33: regs->lo = value;break;
    case 34: regs->hi = value;break;
    case 35: regs->badvaddr = value;break;
    case 36: regs->cause = value;break;
    case 37: regs->epc = value;break;
  }
}

long get_child_eip(pid_t pid)
{
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, pid, 0, &regs);
    return regs.epc;
}


void dump_process_memory(pid_t pid, uintptr_t from_addr, uintptr_t to_addr, char *data)
{
  int i = 0;
  for (uintptr_t addr = from_addr; addr <= to_addr; ++addr) {
    uintptr_t word = ptrace(PTRACE_PEEKTEXT, pid, addr, 0);
    data[i] = word & 0xFF;
    i++;
  }
}

void modify_process_memory(pid_t pid, uintptr_t from_addr, uintptr_t to_addr, uint8_t *data)
{
  int i = 0;
  for (uintptr_t addr = from_addr; addr <= to_addr; ++addr) {
    uintptr_t word = ptrace(PTRACE_PEEKTEXT, pid, addr, 0);
    printf("olddata: %llx\n", word);
    word &= ~(uintptr_t)0xFF;
    word |= (uintptr_t)data[i];
    printf("newdata: %llx\n", word);
    ptrace(PTRACE_POKETEXT, pid, addr, word);
    i++;
  }
}

/* Encapsulates a breakpoint. Holds the address at which the BP was placed
** and the original data word at that address (prior to int3) insertion.
*/
struct debug_breakpoint_t {
    void* addr;
    uintptr_t orig_data;
};


/* Enable the given breakpoint by inserting the trap instruction at its
** address, and saving the original data at that location.
*/
static void enable_breakpoint(pid_t pid, debug_breakpoint* bp)
{
    assert(bp);
    bp->orig_data = ptrace(PTRACE_PEEKTEXT, pid, bp->addr, 0);
    printf("ORIG_DATA : %llx\n", bp->orig_data);
    uintptr_t newdata =  (bp->orig_data & ~(uintptr_t)0xFF) | 0xCC;
    printf("N_DATA : %llx\n", newdata);
    ptrace(PTRACE_POKETEXT, pid, bp->addr, newdata);
}


/* Disable the given breakpoint by replacing the byte it points to with
** the original byte that was there before trap insertion.
*/
static void disable_breakpoint(pid_t pid, debug_breakpoint* bp)
{
    assert(bp);
    uintptr_t data = ptrace(PTRACE_PEEKTEXT, pid, bp->addr, 0);
    assert((data & 0xFF) == 0xCC);
    ptrace(PTRACE_POKETEXT, pid, bp->addr, (data & ~(uintptr_t)0xFF) | (bp->orig_data & 0xFF));
}

static debug_breakpoint* all_bp[100];
int bp_count = 0;


debug_breakpoint* create_breakpoint(pid_t pid, void* addr)
{
    debug_breakpoint* bp = malloc(sizeof(*bp));
    bp->addr = addr;
    enable_breakpoint(pid, bp);
    all_bp[bp_count] = bp;
    bp_count++;
    return bp;
}


void cleanup_breakpoint(debug_breakpoint* bp)
{
    free(bp);
}

int dbglib_continue(pid_t pid)
{
  int wait_status;
  ptrace(PTRACE_CONT, pid, 0, 0);
  wait(&wait_status);
  if (WIFEXITED(wait_status))
      return 0;
  else if (WIFSTOPPED(wait_status)) {
      return 1;
  }
  else
      return -1;
}

int dbglib_single_step(pid_t pid)
{
  int wait_status;
  if (ptrace(PTRACE_SINGLESTEP, pid, 0, 0)) {
      perror("ptrace");
      return -1;
  }
  wait(&wait_status);
  if (WIFEXITED(wait_status))
      return 0;
  else if (WIFSTOPPED(wait_status)) {
      return 1;
  }
  else
      return -1;
}
