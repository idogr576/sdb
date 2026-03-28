#pragma once
#include <gelf.h>
#include <sys/types.h>
#include <stdbool.h>

#include "tracee.h"

void breakpoint_init(tracee *tracee);

void breakpoint_list(tracee *tracee);

void breakpoint_set_verbose(tracee *tracee, GElf_Addr addr, bool verbose);
void breakpoint_set(tracee *tracee, GElf_Addr addr);

void breakpoint_unset_verbose(tracee *tracee, GElf_Addr addr, bool verbose);
void breakpoint_unset(tracee *tracee, GElf_Addr addr);

void breakpoint_step(tracee *tracee);
