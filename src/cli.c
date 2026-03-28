#define _GNU_SOURCE
#include <stdio.h>
#include <readline/readline.h>
#include <readline/history.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "logger.h"

#include "cli.h"
#include "tracee.h"
#include "operation.h"
#include "print.h"

void cli_init()
{
    rl_bind_key('\t', NULL);
}

char *get_last_command()
{
    if (!history_length)
    {
        return NULL;
    }
    HIST_ENTRY *e = history_get(history_base + history_length - 1);
    return strdup(e->line);
}

command_op read_command(tracee *tracee, char *prefix)
{
    char *cmdline = NULL;
    char prompt[MAX_PROMPT_SIZE] = {0};
    char chr_op;
    command_op cmd_op = {NULL, NULL};

    snprintf(prompt, sizeof(prompt), YELLOW("%s "), prefix);
    cmdline = readline(prompt);
    if (!cmdline)
    {
        LOG_DEBUG("cannot read line from user");
        goto error;
    }
    if (*cmdline)
    {
        add_history(cmdline);
    }
    else if (tracee->state.start)
    {
        // empty cmdline means using the last command
        cmdline = get_last_command();
    }
    LOG_DEBUG("read: \"%s\"", cmdline);
    cmd_op.cmdline = cmdline;

    chr_op = tolower(cmdline[0]);

    switch (chr_op)
    {
    case 'r':
        cmd_op.func_op = run_op;
        break;

    case 'b':
        cmd_op.func_op = breakpoint_op;
        break;

    case 'c':
        cmd_op.func_op = continue_op;
        break;

    case 'n':
        cmd_op.func_op = next_op;
        break;

    case 'p':
        cmd_op.func_op = print_op;
        break;

    case 'x':
        cmd_op.func_op = examine_op;
        break;

    case 'h':
        cmd_op.func_op = help_op;
        break;

    case 'q':
        cmd_op.func_op = quit_op;
        break;

    case 'i':
        cmd_op.func_op = info_op;
        break;

    case 's':
        cmd_op.func_op = (strlen(cmd_op.cmdline) == 1 ? step_op : set_op);
        break;

    default:
        cmd_op.func_op = NULL;
    }

    return cmd_op;

error:
    // define error as quit op
    if (cmdline)
    {
        free(cmdline);
    }
    return (command_op){.cmdline = "q", .func_op = quit_op};
}
