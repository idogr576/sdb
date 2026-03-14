#include <sys/ptrace.h>
#include <errno.h>
#include "logger.h"
#include <gelf.h>

#include "utils/data.h"

size_t get_format_unit_size(char fmt)
{
    size_t size;
    switch (fmt)
    {
    case 'x':
    case 'd':
        size = sizeof(int);
        break;
    case 'c':
    case 's':
        size = sizeof(char);
        break;
    default:
        size = 1;
    }
    return size;
}

/*
read size bytes from tracee memory at address addr.
return the number of bytes read. on success, the return value will be equal to size.
*/
size_t read_tracee_mem(tracee *tracee, GElf_Addr addr, uint8_t *data, size_t n)
{
    uint8_t retval;
    size_t read_size = 0;
    for (size_t i = 0; i < n; i++)
    {
        errno = 0;
        retval = (uint8_t)ptrace(PTRACE_PEEKDATA, tracee->pid, addr + i * sizeof(*data), 0);
        if (!errno)
        {
            data[i] = retval;
            read_size += sizeof(retval);
            continue;
        }
        LOG_ERROR("error in reading tracee's mem: %s", strerror(errno));
        break;
    }
    return read_size;
}

uint8_t singlebyte_memset(tracee *tracee, GElf_Addr addr, uint8_t value)
{
    uint8_t orig = 0;
    union
    {
        void *word;
        uint8_t byte;
    } data;
    data.word = (void *)ptrace(PTRACE_PEEKDATA, tracee->pid, addr, 0);
    orig = data.byte;
    data.byte = value;
    ptrace(PTRACE_POKEDATA, tracee->pid, addr, data.word);
    return orig;
}
