#define STB_DS_IMPLEMENTATION
#include "utils/stb_ds.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include "logger.h"

#include "breakpoint.h"
#include "registers.h"
#include "print.h"
#include "utils/data.h"

#define BP_OPCODE 0xCC
#define BP_OPCODE_SIZE 1

void breakpoint_init(tracee *tracee)
{
    LOG_DEBUG("initialize breakpoint hashmap");
    tracee->breakpoints = NULL;
}

void breakpoint_list(tracee *tracee)
{
    LOG_DEBUG("found %d breakpoints\n", hmlen(tracee->breakpoints));
    for (int i = 0; i < hmlen(tracee->breakpoints); i++)
    {
        PRINT(YELLOW("[%d]\t") BLUE("%#016lx\n"), i, tracee->breakpoints[i].key);
    }
    PRINT("\n");
}

void breakpoint_set(tracee *tracee, GElf_Addr addr)
{
    if (hmgetp_null(tracee->breakpoints, addr))
    {
        PRINT(RED("breakpoint at %#lx already set\n"), addr);
        return;
    }
    uint8_t orig = singlebyte_memset(tracee, addr, BP_OPCODE);
    hmput(tracee->breakpoints, addr, orig);
    LOG_DEBUG("there are now %d breakpoints\n", hmlen(tracee->breakpoints));
}

void breakpoint_unset(tracee *tracee, GElf_Addr addr)
{
    hm_t e = hmgetp_null(tracee->breakpoints, addr);
    if (!e)
    {
        PRINT(RED("did not find breakpoint at %#lx") "\n", addr);
        return;
    }
    singlebyte_memset(tracee, addr, e->value);
    hmdel(tracee->breakpoints, addr);
}

void breakpoint_step(tracee *tracee)
{
    /*
    1. check if current rip is on a breakpoint. if not, return
    2. write original byte to tracee's mem
    3. move rip 1 bytes back
    4. move a single step
    5. write the opcode back
    */
    // step 1
    struct user_regs_struct regs = get_tracee_registers(tracee);
    GElf_Addr bprip = (GElf_Addr)regs.rip - BP_OPCODE_SIZE;
    hm_t e = hmgetp_null(tracee->breakpoints, bprip);
    if (!e)
    {
        return;
    }
    // step 2
    singlebyte_memset(tracee, bprip, e->value);

    // step 3
    set_register_value(tracee, "rip", bprip);

    // step 4
    ptrace(PTRACE_SINGLESTEP, tracee->pid, 0, 0);
    waitpid(tracee->pid, 0, 0);

    // step 5
    singlebyte_memset(tracee, bprip, BP_OPCODE);
}
