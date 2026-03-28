#pragma once
#include "tracee.h"

#define IS_QUIT_OP(command_op) (command_op.func_op == quit_op)

void run_op(tracee *tracee, char *cmd);

void continue_op(tracee *tracee, char *cmd);

void next_op(tracee *tracee, char *cmd);

void step_op(tracee *tracee, char *cmd);

void examine_op(tracee *tracee, char *cmd);

void print_op(tracee *tracee, char *cmd);

void breakpoint_op(tracee *tracee, char *cmd);

void help_op(tracee *tracee, char *cmd);

void quit_op(tracee *tracee, char *cmd);

void info_op(tracee *tracee, char *cmd);

void set_op(tracee *tracee, char *cmd);
