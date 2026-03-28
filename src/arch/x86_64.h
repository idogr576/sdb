#pragma once
#include <sys/types.h>

#include "tracee.h"

#define OPCODE_MAX_SIZE 15
#define OPCODE_MAX_REPR 256

int get_next_instruction(tracee *tracee, char *buffer, size_t maxlen);

void x86_64_disassemble(tracee *tracee, GElf_Addr addr, size_t opcodes);
