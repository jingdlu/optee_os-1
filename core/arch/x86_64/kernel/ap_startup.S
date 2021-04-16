/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2018, Intel Corporation
 */

#include <asm.h>
#include <descriptor.h>

#define MSR_EFER   0xc0000080
#define EFER_LME   0x00000100
#define PAT_MSR    0x277
#define CACHE_MODE 0x70106

#define KERNEL_STACK_SIZE 4096

.align 8
.text

.global ap_entry_32

//Jump from realmode
.code32
ap_entry_32:
	/* reload our segments */
    movw $DATA_SELECTOR, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %fs
    movw %ax, %ss
    movw %ax, %gs
    movw %ax, %ss

    /* Calculate APs index */
    mov $1, %eax
    lea optee_cpu_num, %ecx
    lock xadd %eax, (%ecx)

    /* store APs index in edi */
    mov %eax, %edi

    inc %eax
    mov $KERNEL_STACK_SIZE, %edx
    mul %edx
    /* set the kernel stack */
    lea (_kstack)(%eax), %esp

    /* PAE bit must be enabled  for 64 bit paging*/
    mov %cr4, %eax
    bts $(5), %eax
    mov %eax, %cr4

    /* load the physical pointer to the top level page table */
    lea g_pml4_init, %eax
    mov %eax, %cr3

    /* Long Mode Enabled at this point*/
    mov $MSR_EFER ,%ecx
    rdmsr
    or  $EFER_LME,%eax
    wrmsr

    /* setting the PAT MSRs, why? */
    mov $PAT_MSR, %ecx
    mov $CACHE_MODE, %eax
    mov $CACHE_MODE, %edx
    wrmsr

    /*
     * Enabling Paging and from this point we are in
     * 32 bit compatibility mode
     */
    mov %cr0,  %eax
    btsl $(31), %eax
    mov %eax,  %cr0

    /* Using long-jump jump to 64 bit mode */
    pushl $CODE_64_SELECTOR
    lea ap_farjump64, %eax
    pushl %eax
    retf

.code64
ap_farjump64:

    lgdt _gdtr

    lidt _idtr

    call setup_cpu_id

    call core_mmu_init

    call core_init_mmu_map_secondary

    call generic_boot_init_secondary

    call sm_sched_nonsecure
0:
    hlt
    pause
    jmp 0b

