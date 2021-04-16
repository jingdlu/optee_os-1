/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2018, Intel Corporation
 */

#ifndef __DRIVER_APIC_H
#define __DRIVER_APIC_H
#include <types_ext.h>
#include <kernel/interrupt.h>
#include <x86.h>

void apic_init(void);
void restore_pic(void);
void lapic_software_disable(void);
void apic_it_handle(x86_iframe_t *frame);
bool broadcast_init(void);
bool broadcast_startup(uint32_t vector);

#endif /*__DRIVER_APIC_H*/

