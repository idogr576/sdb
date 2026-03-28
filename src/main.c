#include <stdio.h>
#include <sys/ptrace.h>
#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include "logger.h"

#include "cli.h"
#include "operation.h"
#include "elf/symbols.h"
#include "utils/path.h"
#include "tracee.h"
#include "arch/x86_64.h"
#include "breakpoint.h"
#include "print.h"

int main(int argc, char *argv[])
{
    char binary_path[PATH_MAX_LEN] = {0};
    pid_t _pid;
    int wstatus;

    logger_initConsoleLogger(stderr);
    logger_setLevel(LogLevel_FATAL);

    if (argc < 2)
    {
        PRINT("usage: %s <binary path> <args>\n", argv[0]);
        goto error;
    }
    strncpy(binary_path, argv[1], sizeof(binary_path));

    if (!binary_path_exists(binary_path, sizeof(binary_path)))
    {
        goto error;
    }

    _pid = fork();

    if (_pid == -1)
    {
        LOG_ERROR("[parent] error forking the process");
        goto error;
    }
    else if (_pid) // parent process
    {
        state _state = {.start = false, .is_running = false};
        tracee tracee = {.pid = _pid, .state = _state};

        waitpid(tracee.pid, &wstatus, 0); // wait for the tracee to initiate
        if (!WIFSTOPPED(wstatus))
        {
            LOG_ERROR("[parent] child process didn't stop as intended!\n");
            goto error;
        }
        ptrace(PTRACE_SETOPTIONS, tracee.pid, 0, PTRACE_O_TRACEEXEC | PTRACE_O_EXITKILL);
        // load the symbol table before getting commands
        symtab_elf_load(binary_path, &tracee.symtab);
        // initialize breakpoints hashmap
        breakpoint_init(&tracee);

        LOG_DEBUG("symtab: size = %d", tracee.symtab.size);
        ptrace(PTRACE_CONT, tracee.pid, 0, 0);

        // start the main loop
        char instruction[OPCODE_MAX_REPR] = {0};
        command_op cmd_op;
        cli_init();
        do
        {
            if (tracee.state.start)
            {
                get_next_instruction(&tracee, instruction, sizeof(instruction));
                printf("\n%s\n", instruction);
            }
            cmd_op = read_command(&tracee, ">>");
            if (cmd_op.func_op)
            {
                cmd_op.func_op(&tracee, cmd_op.cmdline);
            }
            if (tracee.state.is_running)
            {
                waitpid(tracee.pid, &wstatus, 0);
                LOG_DEBUG("waitpid catch status %d", wstatus);
                tracee.state.is_running = !WIFSTOPPED(wstatus);
            }
            if (cmd_op.cmdline)
            {
                free(cmd_op.cmdline);
            }
        } while (!WIFEXITED(wstatus) && !IS_QUIT_OP(cmd_op));
    }
    else // child process
    {
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        raise(SIGSTOP);
        // tracer continue execution!
        char **exec_argv = (char **)malloc(argc * sizeof(char *));
        if (!exec_argv)
        {
            goto error;
        }
        exec_argv[0] = binary_path;
        exec_argv[argc - 1] = NULL;
        for (int i = 1; i < argc - 1; i++)
        {
            exec_argv[i] = argv[i + 1];
        }
        execv(binary_path, exec_argv);
    }

    return 0;

error:
    if (errno)
    {
        char *err = strerror(errno);
        LOG_ERROR(err);
    }
    return errno;
}