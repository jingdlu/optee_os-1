// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2018 Intel Corporation
 */

#include <x86.h>
#include <assert.h>
#include <kernel/misc.h>

size_t get_core_pos(void)
{
    assert(thread_get_exceptions() & THREAD_EXCP_FOREIGN_INTR);
    return x86_read_gs_with_offset(0);
}

size_t get_core_pos_mpidr(uint32_t mpidr __unused)
{
	return 0;
}
