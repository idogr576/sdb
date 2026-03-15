#pragma once
#include <gelf.h>
#include <sys/types.h>

#include "elf/symbols.h"
#include "registers.h"
#include "tracee.h"

#define INVALID_ADDRESS (GElf_Addr)-1
#define INVALID_VALUE \
    (Value) { .addr = INVALID_ADDRESS }

#define IS_INVALID_VALUE(value) (value.addr == INVALID_VALUE.addr)

#define PREFIX_HEX_SIZE 2
#define PREFIX_DEC_SIZE 0

// macros for identifying prefix type
#define IS_ADDR_HEX(x) (!strncmp(x, "0x", PREFIX_HEX_SIZE))
#define IS_ADDR_DEC(x) (strlen(x) > PREFIX_DEC_SIZE && isdigit(x[PREFIX_DEC_SIZE]))

typedef enum AddrType
{
    DIRECT,
    SYMBOL,
    INVALID,
} AddrType;

typedef enum ValueType
{
    TYPE_ADDRESS,
    TYPE_SYMBOL,
    TYPE_REGISTER,
    TYPE_INVALID,
} ValueType;

typedef union Value
{
    GElf_Addr addr;
    reg_t reg;
} Value;

ValueType identify_value_type(tracee *tracee, char *value_str);

GElf_Addr parse_direct_address(char *addr_repr);

GElf_Addr resolve_address(tracee *tracee, ValueType type, char *addr_repr);

Value resolve_value(tracee *tracee, char *addr_repr);
