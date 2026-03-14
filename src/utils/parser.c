#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "logger.h"
#include "elf/symbols.h"
#include "utils/parser.h"

ValueType identify_value_type(char *value_str, symtab *symtab)
{
    if (isdigit(value_str[0]))
    {
        return TYPE_ADDRESS;
    }
    if (value_str[0] == '$')
    {
        return TYPE_REGISTER;
    }
    return symtab_find_sym(symtab, value_str) == NULL ? TYPE_INVALID : TYPE_SYMBOL;
}

GElf_Addr parse_direct_address(char *addr_repr)
{
    if (IS_ADDR_HEX(addr_repr))
    {
        return (GElf_Addr)strtoull(addr_repr + PREFIX_HEX_SIZE, NULL, 16);
    }
    if (IS_ADDR_DEC(addr_repr))
    {

        return (GElf_Addr)strtoull(addr_repr + PREFIX_DEC_SIZE, NULL, 10);
    }
    return INVALID_ADDRESS;
}

GElf_Addr resolve_address(ValueType type, pid_t pid, symtab *symtab, char *addr_repr)
{
    if (type == TYPE_ADDRESS)
    {
        LOG_DEBUG("found direct address: %s", addr_repr);
        return parse_direct_address(addr_repr);
    }
    if (type == TYPE_SYMBOL)
    {
        GElf_Sym *sym = symtab_find_sym(symtab, addr_repr);
        if (!sym)
        {
            goto error;
        }

        GElf_Addr addr = symtab_get_dyn_sym_addr(pid, sym);
        LOG_DEBUG("%s = %#lx\n", addr_repr, addr);
        return addr;
    }
error:
    return INVALID_ADDRESS;
}

Value resolve_value(tracee *tracee, char *addr_repr)
{
    Value val;
    ValueType type = identify_value_type(addr_repr, &tracee->symtab);
    // check if register or address
    switch (type)
    {
    case TYPE_REGISTER:
        reg_t reg = get_register_value(tracee, addr_repr + 1);
        if (reg == INVALID_REGISTER_VALUE)
        {
            val = INVALID_VALUE;
        }
        else
        {
            val.reg = reg;
        }
        break;

    case TYPE_ADDRESS:
    case TYPE_SYMBOL:
        GElf_Addr addr = resolve_address(type, tracee->pid, &tracee->symtab, addr_repr);
        if (addr == INVALID_ADDRESS)
        {
            LOG_ERROR("cannot resolve address %s", addr_repr);
            val = INVALID_VALUE;
        }
        else
        {
            val.addr = addr;
        }
        break;
    default:
        LOG_ERROR("address does not match any kind");
        val = INVALID_VALUE;
    }
    return val;
}