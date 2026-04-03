#pragma once
#include <sys/types.h>

#include "tracee.h"

#define OPCODE_MAX_SIZE 15
#define OPCODE_MAX_REPR 256

/* given a buffer with the formatted disassembly (including colors and addresses),
   check if it holds a "call" instruction efficiently */
#define IS_CALL_INS(buffer) !strncmp(buffer + 32, "call", 4)

int get_next_instruction(tracee *tracee, char *buffer, size_t maxlen);

void x86_64_disassemble(tracee *tracee, GElf_Addr addr, size_t opcodes);
