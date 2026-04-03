#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include "external/logger.h"
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

// mark unused parameters to disable compilation warnings
#define UNUSED(x) (void)(x)

#define FMTSIZE 32

void run_op(tracee *tracee, char *cmd)
{
    UNUSED(cmd);
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
    UNUSED(cmd);
    LOG_DEBUG("operation CONTINUE");
    if (!tracee->state.start)
    {
        PRINT(RED("start execution with \"r\"\n"));
        return;
    }
    breakpoint_step(tracee);
    ptrace(PTRACE_CONT, tracee->pid, 0, 0);
    tracee->state.is_running = true;
}

void step_op(tracee *tracee, char *cmd)
{
    UNUSED(cmd);
    LOG_DEBUG("STEP OPERATION");
    if (tracee->state.start && !tracee->state.is_running)
    {
        breakpoint_step(tracee);
        ptrace(PTRACE_SINGLESTEP, tracee->pid, 0, 0);
        tracee->state.is_running = true;
    }
}

/* Go to next instruction but donʻt dive into functions. */
void next_op(tracee *tracee, char *cmd)
{
    LOG_DEBUG("NEXT OPERATION");
    char instruction[OPCODE_MAX_REPR] = {0};
    int length = get_next_instruction(tracee, instruction, sizeof(instruction));

    // check if we see a call instruction
    if (!IS_CALL_INS(instruction))
    {
        step_op(tracee, cmd);
        return;
    }
    // step 1: set a temporary breakpoint at the next instruction address
    GElf_Addr next_rip = get_program_counter(tracee) + length;
    breakpoint_set_verbose(tracee, next_rip, false);
    LOG_DEBUG("set temporary breakpoint");

    // step 2: continue until this address is reached (+int3 single-byte offset)
    int wstatus;
    while (next_rip + BP_OPCODE_SIZE != get_program_counter(tracee))
    {
        continue_op(tracee, cmd);
        waitpid(tracee->pid, &wstatus, 0);
    }
    tracee->state.is_running = !WIFSTOPPED(wstatus);

    // step 3: unset the temporary breakpoint
    breakpoint_unset_verbose(tracee, next_rip, false);
    LOG_DEBUG("unset temporary breakpoint");

    // step 4: revert rip 1 bytes backwards (-int3 single-byte offset)
    set_register_value(tracee, "rip", next_rip);
}

void examine_op(tracee *tracee, char *cmd)
{
    LOG_DEBUG("operation EXAMINE");
    char buf[BUFSIZ] = {0};
    char safe_fmt_string[FMTSIZE] = {0};
    char fmt = 'x';
    int n = 1;

    // safely make the fmt string to prevert overflow on buf
    snprintf(safe_fmt_string, sizeof(safe_fmt_string), "x/%%d%%c %%%lds", sizeof(buf) - 1);
    // try to read the input
    if (sscanf(cmd, safe_fmt_string, &n, &fmt, buf) != 3 || !strlen(buf))
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
            PRINT(BLUE("%016" PRIX64) " %#08x\n", val.addr + i * sizeof(*p), p[i]);
        }
        if (fmt == 'd')
        {
            int32_t *p = (int32_t *)data;
            PRINT(BLUE("%016" PRIX64) " %d\n", val.addr + i * sizeof(*p), p[i]);
        }
        if (fmt == 'b')
        {
            uint8_t *p = (uint8_t *)data;
            PRINT(BLUE("%016" PRIX64) " %#02hhx\n", val.addr + i * sizeof(*p), p[i]);
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
    char output[BUFSIZ] = {0};
    char safe_fmt_string[FMTSIZE] = {0};
    char fmt = 'x';
    // safely make the fmt string to prevert overflow on buf
    snprintf(safe_fmt_string, sizeof(safe_fmt_string), "p/%%c %%%lds", sizeof(buf) - 1);
    // try to read the input
    if (sscanf(cmd, safe_fmt_string, &fmt, buf) != 2)
    {
        snprintf(safe_fmt_string, sizeof(safe_fmt_string), "p %%%lds", sizeof(buf) - 1);
        sscanf(cmd, safe_fmt_string, buf);
    }
    if (!strlen(buf))
    {
        LOG_ERROR("cannot read cmd to buffer");
        PRINT(RED("usage: p/<fmt> <value>, default <fmt> is 'x'\n"));
        return;
    }
    Value val = resolve_value(tracee, buf);
    if (IS_INVALID_VALUE(val))
    {
        PRINT(RED("invalid value to print!\nNot a symbol, register or direct address\n"));
        return;
    }
    ValueType type = identify_value_type(tracee, buf);
    if (type == TYPE_REGISTER)
    {
        if (fmt == 'd')
            strncpy(output, BLUE("%s") " = %llu\n", sizeof(output));
        else
            strncpy(output, BLUE("%s") " = %#llx\n", sizeof(output));
    }
    else
    {
        if (fmt == 'd')
            strncpy(output, BLUE("%s") " = %ld\n", sizeof(output));
        else
            strncpy(output, BLUE("%s") " = %#lx\n", sizeof(output));
    }
    PRINT(output, buf, val);
}

void breakpoint_op(tracee *tracee, char *cmd)
{
    LOG_DEBUG("operation BREAKPOINT");
    if (strlen(cmd) == 1)
    {
        breakpoint_list(tracee);
    }
    Value val;
    if (cmd[1] == ' ')
    {
        val = resolve_value(tracee, &cmd[2]);
        if (IS_INVALID_VALUE(val))
        {
            PRINT(RED("address does not exists\n"));
        }
        else
        {
            breakpoint_set(tracee, val.addr);
        }
    }
    if (cmd[1] == 'd')
    {
        val = resolve_value(tracee, &cmd[3]);
        if (IS_INVALID_VALUE(val))
        {
            PRINT(RED("address does not exists\n"));
        }
        else
        {
            breakpoint_unset(tracee, val.addr);
        }
    }
}

void help_op(tracee *tracee, char *cmd)
{
    UNUSED(tracee);
    UNUSED(cmd);
    PRINT("Available Commands:\n");
    PRINT("----------------------------------------------\n");
    PRINT(GREEN("r") "   - start program\n");
    PRINT(GREEN("c") "   - continue execution of program\n");
    PRINT(GREEN("s") "   - go to next instruction\n");
    PRINT(GREEN("n") "   - go to next instruction but step over functions\n");
    PRINT(GREEN("x") "   - examine memory and registers\n");
    PRINT(GREEN("p") "   - print variables and registers value\n");
    PRINT(GREEN("b") "   - set and unset breakpoints\n");
    PRINT(GREEN("i") "   - show info on symbols / registers / other\n");
    PRINT(GREEN("set") " - set value to address in memory or register\n");
    PRINT(GREEN("q") "   - quit sdb\n");
    PRINT(GREEN("h") "   - print this help message\n");
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
    PRINT(BLUE("set main 0xcc") YELLOW("           // set byte 0xcc for address of main\n"));
    PRINT(BLUE("set $rax 0") YELLOW("              // set value of $rax to be 0\n"));
    PRINT(BLUE("set $rax $rbx") YELLOW("           // set value of $rax to be as $rbx\n"));
    PRINT("\n");
}

void quit_op(tracee *tracee, char *cmd)
{
    UNUSED(tracee);
    UNUSED(cmd);
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
            PRINT(BLUE("%#016lx") " %s\n", base_addr + sym_value, tracee->symtab.sym_names[i]);
        }
    }
    else if (type == 'r')
    {
        struct user_regs_struct regs = get_tracee_registers(tracee);
        reg_t *reg = (reg_t *)&regs;
        for (size_t i = 0; i < COUNT_REGS(regs); i++, reg++)
        {
            PRINT(BLUE("%8s") " = %#llx\n", defined_regs[i], *reg);
        }
    }
    else
    {
        PRINT(RED("undefined option after i(nfo)\n"));
    }
    PRINT("\n");
}

void set_op(tracee *tracee, char *cmd)
{
    LOG_DEBUG("SET OPERATION\n");
    char varname[BUFSIZ] = {0};
    char value[BUFSIZ] = {0};
    char safe_fmt_string[FMTSIZE] = {0};
    // safely make the fmt string to prevert overflow on buffers
    snprintf(safe_fmt_string, sizeof(safe_fmt_string), "set %%%lds %%%lds", sizeof(varname) - 1, sizeof(value) - 1);
    LOG_DEBUG("fmt string is \"%s\"\n", safe_fmt_string);
    // try to read the input
    if (sscanf(cmd, safe_fmt_string, varname, value) != 2)
    {
        PRINT(RED("usage: set <variable> <value>") "\n");
        return;
    }
    LOG_DEBUG("varname = %s, value = %s\n", varname, value);
    Value var = resolve_value(tracee, varname);
    if (IS_INVALID_VALUE(var))
    {
        PRINT(RED("invalid variable to set!\nNot a symbol, register or numeric value\n"));
        return;
    }
    Value val = resolve_value(tracee, value);
    if (IS_INVALID_VALUE(val))
    {
        PRINT(RED("invalid value to set!\nNot a symbol, register or numeric value\n"));
        return;
    }
    ValueType type = identify_value_type(tracee, varname);

    switch (type)
    {
    case TYPE_ADDRESS:
    case TYPE_SYMBOL:
        // set a single bytes to this address
        uint8_t byte = (uint8_t)val.addr;
        PRINT(BLUE("attempting to set byte %#x to address %#lx") "\n", byte, var.addr);
        singlebyte_memset(tracee, var.addr, byte);
        PRINT(GREEN("success!") "\n");
        break;
    case TYPE_REGISTER:
        // skipping the '$' prefix of register name
        if (!set_register_value(tracee, varname + 1, val.reg))
        {
            PRINT(GREEN("successfully set %s to %#llx") "\n", varname, val.reg);
        }
        break;
    case TYPE_INVALID:
    default:
        // this code should never be reached. it it does, there is a bug
        LOG_ERROR(RED("this log should not appear. please check the code integrity") "\n");
    }
}
