#include <sys/ptrace.h>
#include <sys/user.h>
#include <string.h>
#include <gelf.h>
#include "logger.h"

#include "registers.h"
#include "tracee.h"
#include "print.h"

const char *defined_regs[] = {"r15", "r14", "r13", "r12",
                              "rbp", "rbx", "r11", "r10", "r9", "r8", "rax",
                              "rcx", "rdx", "rsi", "rdi", "orig_rax", "rip",
                              "cs", "eflags", "rsp", "ss", "fs_base", "gs_base",
                              "ds", "es", "fs", "gs"};

struct user_regs_struct get_tracee_registers(tracee *tracee)
{
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, tracee->pid, 0, &regs);
    return regs;
}

reg_t get_register_value(tracee *tracee, char *reg_name)
{
    struct user_regs_struct regs = get_tracee_registers(tracee);
    LOG_DEBUG("finish getting regs");
    reg_t *regp = (reg_t *)&regs;

    LOG_DEBUG("%d regs.\nsanity check: %s = %ld = %ld. ", COUNT_REGS(regs), defined_regs[10], *(regp + 10), regs.rax);

    for (size_t i = 0; i < COUNT_REGS(regs); i++)
    {
        if (!strcmp(reg_name, defined_regs[i]))
        {
            LOG_DEBUG("matching register %s, value is %#llx\n", defined_regs[i], *(regp + i));
            return *(regp + i);
        }
    }
    LOG_ERROR("register \"%s\" not found", reg_name);
    return INVALID_REGISTER_VALUE;
}

error_t set_register_value(tracee *tracee, char *reg_name, reg_t value)
{
    struct user_regs_struct regs = get_tracee_registers(tracee);
    reg_t *regp = (reg_t *)&regs;
    for (size_t i = 0; i < COUNT_REGS(regs); i++)
    {
        if (!strcmp(reg_name, defined_regs[i]))
        {
            LOG_DEBUG("matching register %s\n", defined_regs[i]);
            break;
        }
        regp++;
    }
    *regp = value;
    ptrace(PTRACE_SETREGS, tracee->pid, 0, &regs);
    return 0;
}

GElf_Addr get_program_counter(tracee *tracee)
{
    struct user_regs_struct regs = get_tracee_registers(tracee);
    return (GElf_Addr)regs.rip;
}
