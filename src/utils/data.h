#pragma once
#include <stddef.h>
#include <gelf.h>
#include "tracee.h"

size_t get_format_unit_size(char fmt);

size_t read_tracee_mem(tracee *tracee, GElf_Addr addr, uint8_t* data, size_t n);

uint8_t singlebyte_memset(tracee *tracee, GElf_Addr addr, uint8_t value);