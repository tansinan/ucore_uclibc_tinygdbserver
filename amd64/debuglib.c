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
#include <sys/reg.h>
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
  return 24; //AMD64
}

uint64_t dbglib_get_child_register_by_gdb_index(struct user_regs_struct *regs, int i, int* bitwidth)
{
  if(i <= 16) *bitwidth = 64;
  else *bitwidth = 32;
  switch(i) {
    case 0: return regs->rax;
    case 1: return regs->rbx;
    case 2: return regs->rcx;
    case 3: return regs->rdx;
    case 4: return regs->rsi;
    case 5: return regs->rdi;
    case 6: return regs->rbp;
    case 7: return regs->rsp;
    case 8: return regs->r8;
    case 9: return regs->r9;
    case 10: return regs->r10;
    case 11: return regs->r11;
    case 12: return regs->r12;
    case 13: return regs->r13;
    case 14: return regs->r14;
    case 15: return regs->r15;
    case 16: return regs->rip;
    case 17: return regs->eflags;
    case 18: return regs->cs;
    case 19: return regs->ss;
    case 20: return regs->ds;
    case 21: return regs->es;
    case 22: return regs->fs;
    case 23: return regs->gs;
  }
  return 0;
}


void dbglib_set_child_register_by_gdb_index(struct user_regs_struct *regs, int i, uintptr_t value)
{
  switch(i) {
    case 0: regs->rax = value;break;
    case 1: regs->rbx = value;break;
    case 2: regs->rcx = value;break;
    case 3: regs->rdx = value;break;
    case 4: regs->rsi = value;break;
    case 5: regs->rdi = value;break;
    case 6: regs->rbp = value;break;
    case 7: regs->rsp = value;break;
    case 8: regs->r8 = value;break;
    case 9: regs->r9 = value;break;
    case 10: regs->r10 = value;break;
    case 11: regs->r11 = value;break;
    case 12: regs->r12 = value;break;
    case 13: regs->r13 = value;break;
    case 14: regs->r14 = value;break;
    case 15: regs->r15 = value;break;
    case 16: regs->rip = value;break;
    case 17: regs->eflags = value;break;
    case 18: regs->cs = value;break;
    case 19: regs->ss = value;break;
    case 20: regs->ds = value;break;
    case 21: regs->es = value;break;
    case 22: regs->fs = value;break;
    case 23: regs->gs = value;break;
  }
}

long get_child_eip(pid_t pid)
{
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, pid, 0, &regs);
    return regs.rip;
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

int resume_from_breakpoint(pid_t pid, debug_breakpoint* bp)
{
    struct user_regs_struct regs;
    int wait_status;

    ptrace(PTRACE_GETREGS, pid, 0, &regs);
    /* Make sure we indeed are stopped at bp */
    assert(regs.rip == (long) bp->addr + 1);

    /* Now disable the breakpoint, rewind EIP back to the original instruction
    ** and single-step the process. This executes the original instruction that
    ** was replaced by the breakpoint.
    */
    regs.rip = (long) bp->addr;
    ptrace(PTRACE_SETREGS, pid, 0, &regs);
    disable_breakpoint(pid, bp);
    if (ptrace(PTRACE_SINGLESTEP, pid, 0, 0)) {
        perror("ptrace");
        return -1;
    }
    wait(&wait_status);

    if (WIFEXITED(wait_status))
        return 0;

    /* Re-enable the breakpoint and let the process run.
    */
    enable_breakpoint(pid, bp);

    if (ptrace(PTRACE_CONT, pid, 0, 0) < 0) {
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
