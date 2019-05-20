/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

#ifndef KERNEL_MISC_H
#define KERNEL_MISC_H

#include <kernel/thread.h>
#include <types_ext.h>

size_t get_core_pos(void);
size_t get_core_pos_mpidr(uint32_t mpidr);

uint32_t read_mode_sp(int cpu_mode);
uint32_t read_mode_lr(int cpu_mode);

static inline uint64_t reg_pair_to_64(uint32_t reg0, uint32_t reg1)
{
	return (uint64_t)reg0 << 32 | reg1;
}

static inline void reg_pair_from_64(uint64_t val, uint32_t *reg0,
			uint32_t *reg1)
{
	*reg0 = val >> 32;
	*reg1 = val;
}

#endif /*KERNEL_MISC_H*/

