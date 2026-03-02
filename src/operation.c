#include <stdio.h>
#include <sys/ptrace.h>
#include "logger.h"
#include <string.h>
#include <stdbool.h>
#include <inttypes.h>

#include "operation.h"
#include "elf/symbols.h"
#include "utils/parser.h"
#include "registers.h"
#include "arch/x86_64.h"
#include "breakpoint.h"
#include "utils/data.h"
#include "print.h"

void run_op(tracee *tracee, char *cmd)
{
    if (tracee->state.start)
    {
        return;
    }
    LOG_DEBUG("operarion RUN");
    PRINT(YELLOW("-----------------------------\n"));
    PRINT(YELLOW("starting execution of program\n"));
    PRINT(YELLOW("-----------------------------") "\n");
    tracee->state.start = true;
    tracee->state.is_running = true;
    ptrace(PTRACE_CONT, tracee->pid, 0, 0);
}

void continue_op(tracee *tracee, char *cmd)
{
    LOG_DEBUG("operation CONTINUE");
    if (!tracee->state.start)
    {
        PRINT(RED("start execution with \"r\"\n"));
        return;
    }
    tracee->state.is_running = true;
    breakpoint_step(tracee);
    ptrace(PTRACE_CONT, tracee->pid, 0, 0);
}

void next_op(tracee *tracee, char *cmd)
{
    LOG_DEBUG("operation STEP");
    if (tracee->state.start && !tracee->state.is_running)
    {
        breakpoint_step(tracee);
        ptrace(PTRACE_SINGLESTEP, tracee->pid, 0, 0);
        tracee->state.is_running = true;
    }
}

void examine_op(tracee *tracee, char *cmd)
{
    LOG_DEBUG("operation EXAMINE");
    char buf[BUFSIZ] = {0};
    char fmt = 'x';
    int n = 1;
    // try to read the input
    if (sscanf(cmd, "x/%d%c %s", &n, &fmt, buf) != 3 || !buf)
    {
        LOG_ERROR("cannot read cmd to buffer");
        PRINT(RED("usage: x/<n><fmt> <value>\n"));
        return;
    }
    Value val = resolve_value(tracee, buf);

    if (IS_INVALID_VALUE(val))
    {
        PRINT(RED("Invalid value to examine!\nNot a symbol, register or direct address\n"));
        return;
    }

    if (fmt == 'i')
    {
        x86_64_disassemble(tracee, val.addr, n);
        return;
    }
    if (!strchr("xdbcs", fmt))
    {
        return;
    }
    size_t unit = get_format_unit_size(fmt);
    uint8_t data[BUFSIZ] = {0};
    size_t size = read_tracee_mem(tracee, val.addr, data, n * unit);
    LOG_DEBUG("read %ld bytes", size);
    if (fmt == 's')
    {
        PRINT(BLUE("%016" PRIX64) " %s\n", val.addr, data);
        return;
    }
    for (int i = 0; i < n; i++)
    {
        if (fmt == 'x')
        {
            uint32_t *p = (uint32_t *)data;
            PRINT(BLUE("%016" PRIX64) " 0x%08lx\n", val.addr + i * sizeof(*p), p[i]);
        }
        if (fmt == 'd')
        {
            int32_t *p = (int32_t *)data;
            PRINT(BLUE("%016" PRIX64) " %d\n", val.addr + i * sizeof(*p), p[i]);
        }
        if (fmt == 'b')
        {
            uint8_t *p = (uint8_t *)data;
            PRINT(BLUE("%016" PRIX64) " 0x%02hhx\n", val.addr + i * sizeof(*p), p[i]);
        }
        if (fmt == 'c')
        {
            char *p = (char *)data;
            PRINT(BLUE("%016" PRIX64) " %c\n", val.addr + i * sizeof(*p), p[i]);
        }
    }
}

void print_op(tracee *tracee, char *cmd)
{
    LOG_DEBUG("operation PRINT");
    char buf[BUFSIZ] = {0};
    char fullfmt[BUFSIZ] = {0};
    char fmt = 'x';
    // try to read the input
    if (sscanf(cmd, "p/%c %s", &fmt, buf) != 2)
    {
        sscanf(cmd, "p %s", buf);
    }
    if (!buf)
    {
        LOG_ERROR("cannot read cmd to buffer");
        PRINT(RED("usage: p/<fmt> <value>, default <fmt> is 'x'\n"));
        return;
    }
    Value val = resolve_value(tracee, buf);
    if (IS_INVALID_VALUE(val))
    {
        PRINT(RED("Invalid value to print!\nNot a symbol, register or direct address\n"));
        return;
    }

    if (fmt == 'd')
    {
        strncpy(fullfmt, BLUE("%s") " = %ld\n", BUFSIZ);
    }
    else
    {
        strncpy(fullfmt, BLUE("%s") " = 0x%lx\n", BUFSIZ);
    }
    PRINT(fullfmt, buf, val);
}

void breakpoint_op(tracee *tracee, char *cmd)
{
    LOG_DEBUG("operation BREAKPOINT");
    if (strlen(cmd) == 1)
    {
        breakpoint_list(tracee);
    }
    if (cmd[1] == ' ')
    {
        Value addr = resolve_value(tracee, &cmd[2]);
        if (!addr.addr)
        {
            PRINT(RED("address does not exists\n"));
        }
        else
        {
            breakpoint_set(tracee, addr.addr);
        }
    }
    if (cmd[1] == 'd')
    {
        Value addr = resolve_value(tracee, &cmd[3]);
        if (!addr.addr)
        {
            PRINT(RED("address does not exists\n"));
        }
        else
        {
            breakpoint_unset(tracee, addr.addr);
        }
    }
}

void help_op(tracee *tracee, char *cmd)
{
    PRINT("Available Commands:\n");
    PRINT("----------------------------------------------\n");
    PRINT(GREEN("r") " - start program\n");
    PRINT(GREEN("c") " - continue execution of program\n");
    PRINT(GREEN("n") " - step to next instructio\n");
    PRINT(GREEN("x") " - examine memory and registers\n");
    PRINT(GREEN("p") " - print variables and registers value\n");
    PRINT(GREEN("b") " - set and unset breakpoints\n");
    PRINT(GREEN("i") " - show info on symbols / registers / other\n");
    PRINT(GREEN("q") " - quit sdb\n");
    PRINT(GREEN("h") " - print this help message\n");
    PRINT("\n\n");
    PRINT(YELLOW("Examples\n"));
    PRINT(YELLOW("----------------------------------------------\n"));
    PRINT(BLUE("p/d $rax") YELLOW("                // print register rax values in decimal\n"));
    PRINT(BLUE("p main") YELLOW("                  // print main symbol address\n"));
    PRINT("\n");
    PRINT(BLUE("x/10i main") YELLOW("              // display 10 instructions starting from address main\n"));
    PRINT(BLUE("x/1x 0x64ffdbb32004") YELLOW("     // display word in hex at the given address in memory\n"));
    PRINT(BLUE("x/100s 0x64ffdbb32004") YELLOW("   // display the string at address, at most 100 chars\n"));
    PRINT("\n");
    PRINT(BLUE("b main") YELLOW("                  // set breakpoint at address main\n"));
    PRINT(BLUE("b") YELLOW("                       // list all breakpoints\n"));
    PRINT(BLUE("bd main") YELLOW("                 // delete breakpoint at main\n"));
    PRINT("\n");
    PRINT(BLUE("i s") YELLOW("                     // show info on all available symbols\n"));
    PRINT(BLUE("i r") YELLOW("                     // show info on all available registers\n"));
    PRINT("\n");
}

void quit_op(tracee *tracee, char *cmd)
{
    PRINT(YELLOW("Goodby from sdb!\n"));
}

void info_op(tracee *tracee, char *cmd)
{
    LOG_DEBUG("INFO OPERATION");
    char type;
    if (sscanf(cmd, "i %c", &type) != 1)
    {
        LOG_ERROR("invalid input");
        PRINT(RED("usage: i <info>\ninfo can be s (symbol) or r (register)\n"));
        return;
    }
    // symbols
    if (type == 's')
    {
        GElf_Addr base_addr = symtab_get_dyn_sym_addr(tracee->pid, tracee->symtab.symbols);
        for (size_t i = 0; i < tracee->symtab.size; i++)
        {
            GElf_Addr sym_value = tracee->symtab.symbols[i].st_value;
            PRINT(BLUE("0x%016lx") " %s\n", base_addr + sym_value, tracee->symtab.sym_names[i]);
        }
    }
    else if (type == 'r')
    {
        struct user_regs_struct regs = get_tracee_registers(tracee);
        reg_t *reg = (reg_t *)&regs;
        for (size_t i = 0; i < COUNT_REGS(regs); i++, reg++)
        {
            PRINT(BLUE("%8s") " = 0x%lx\n", defined_regs[i], *reg);
        }
    }
    else
    {
        PRINT(RED("undefined option after i(nfo)\n"));
    }
    PRINT("\n");
}