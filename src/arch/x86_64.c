#include <sys/ptrace.h>
#include <inttypes.h>
#include <Zydis/Zydis.h>
#include <stdbool.h>
#include "logger.h"

#include "arch/x86_64.h"
#include "registers.h"
#include "tracee.h"
#include "print.h"

void get_current_opcode(tracee *tracee, char *opcode, size_t maxlen)
{
    reg_t rip = get_program_counter(tracee);
    char buffer[OPCODE_MAX_REPR];
    if (!rip)
    {
        LOG_ERROR("cannot access register rip");
        return;
    }
    ZyanU64 runtime_address = rip;
    ZyanU8 data[OPCODE_MAX_SIZE] = {0};
    for (size_t i = 0; i < OPCODE_MAX_SIZE; i++)
    {
        data[i] = (ZyanU8)ptrace(PTRACE_PEEKDATA, tracee->pid, runtime_address + i, 0);
    }
    // 1. Initialize Decoder
    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

    // 2. Initialize Formatter
    ZydisFormatter formatter;
    ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);

    ZydisDecodedInstruction instruction;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
    ZyanUSize offset = 0;
    ZydisDecoderDecodeFull(&decoder, data + offset, sizeof(data) - offset, &instruction, operands);

    // Format the instruction into our buffer
    ZydisFormatterFormatInstruction(&formatter, &instruction, operands,
                                    instruction.operand_count_visible, buffer, sizeof(buffer),
                                    runtime_address, ZYAN_NULL);

    snprintf(opcode, maxlen, BLUE("%016" PRIX64) YELLOW("  %s"), runtime_address, buffer);
}

void x86_64_disassemble(tracee *tracee, GElf_Addr addr, size_t opcodes)
{
    char buffer[OPCODE_MAX_REPR];
    ZyanU8 data[BUFSIZ] = {0};
    ZyanU64 runtime_address = addr;
    for (size_t i = 0; i < OPCODE_MAX_SIZE * opcodes; i++)
    {
        data[i] = (ZyanU8)ptrace(PTRACE_PEEKDATA, tracee->pid, runtime_address + i, 0);
    }
    // 1. Initialize Decoder
    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

    // 2. Initialize Formatter
    ZydisFormatter formatter;
    ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);

    ZydisDecodedInstruction instruction;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
    ZyanUSize offset = 0;
    ZydisDecoderDecodeFull(&decoder, data + offset, sizeof(data) - offset, &instruction, operands);

    // Format the instruction into our buffer
    ZydisFormatterFormatInstruction(&formatter, &instruction, operands,
                                    instruction.operand_count_visible, buffer, sizeof(buffer),
                                    runtime_address, ZYAN_NULL);

    // 3. Loop and Decode - not for now
    while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, data + offset, sizeof(data) - offset,
                                               &instruction, operands)))
    {

        if (!opcodes--)
        {
            break;
        }
        // Format the instruction into our buffer
        ZydisFormatterFormatInstruction(&formatter, &instruction, operands,
                                        instruction.operand_count_visible, buffer, sizeof(buffer),
                                        runtime_address, ZYAN_NULL);

        PRINT(BLUE("%016" PRIX64) "  %s\n", runtime_address, buffer);

        offset += instruction.length;
        runtime_address += instruction.length;
    }
}