// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2019, Intel Corporation
 */

#include <stdio.h>
#include <trace.h>
#include <string.h>
#include <x86.h>
#include <mm/core_mmu.h>
#include <mm/core_memprot.h>
#include <kernel/generic_boot.h>
#include <kernel/misc.h>
#include <drivers/apic.h>

typedef struct {
	uint16_t	limit;
	uint32_t	base;
} __packed gdtr32_t, idtr32_t;

typedef struct {
	uint16_t	limit;
	uint64_t	base;
} __packed gdtr64_t, idtr64_t;

#define AP_STARTUP_ADDR  0x80000
#define AP_STARTUP_VADDR 0x13851000

#define ALIGN_B(value, align) \
	((uint64_t)(value) & (~((uint64_t)(align) - 1ULL)))
#define ALIGN_F(value, align) \
	ALIGN_B((uint64_t)value + (uint64_t)align - 1, align)

#define PTCH 0x00

#ifdef BREAK_AT_FIRST_COMMAND
#define REAL_MODE_CODE_START 2
#else
#define REAL_MODE_CODE_START 0
#endif

#define REAL_MODE_STARTUP				( 1 + REAL_MODE_CODE_START)
#define GDTR_OFFSET_IN_CODE				( 7 + REAL_MODE_CODE_START)
#define CPU_STARTUP32					(22 + REAL_MODE_CODE_START)

#define GDTR_OFFSET_IN_PAGE				ALIGN_F(sizeof(real_mode_code), 0x8)
#define GDT_OFFSET_IN_PAGE				(GDTR_OFFSET_IN_PAGE + 8)

extern void ap_entry_32();
extern int optee_cpu_waken_up;

#define TSC_PER_MS 2800000
static void wait_us(uint64_t us)
{
    uint64_t end_tsc;
    uint64_t val;

    val = rdtsc();

    end_tsc = val + (us * TSC_PER_MS / 1000ULL);

    while (val < end_tsc) {
        __asm__ __volatile__("pause");
        val = rdtsc();
    }
}

static uint8_t real_mode_code[] = {
#ifdef BREAK_AT_FIRST_COMMAND
	0xEB, 0xFE,                     /* jmp $ */
#endif
	0xB8, PTCH, PTCH,               /* 00: mov REAL_MODE_START_UP, %ax */
	0x8E, 0xD8,                     /* 03: mov %ax, %ds */
	0x8D, 0x36, PTCH, PTCH,         /* 05: lea GDTR_OFFSET_IN_PAGE, %si */
	0x0F, 0x01, 0x14,               /* 09: lgdt fword ptr [si] */
	0x0F, 0x20, 0xC0,               /* 12: mov %cr0, %eax */
	0x0C, 0x01,                     /* 15: or $1, %al */
	0x0F, 0x22, 0xC0,               /* 17: mov %eax, %cr0 */
	0x66, 0xEA,                     /* 20: fjmp CS:CPU_STARTUP32 */
	PTCH, PTCH, PTCH, PTCH,         /* 22: CPU_STARTUP32 */
	0x08, 0x00,                     /* 26: CS_VALUE=0x08 */
};

static void setup_sipi_page(uint64_t sipi_page, uint32_t ap_startup_pa)
{
	uint8_t *code_to_patch = (uint8_t *)sipi_page;
	gdtr32_t *gdtr_32;

	static const uint64_t gdt_32_table[] __attribute__ ((aligned(16))) = {
		0x0,
		0x00cf9a000000ffffULL, //32bit CS
		0x00cf92000000ffffULL, //32bit DS
		0x0,
		0x0,
		0x0,
		0x00af9a000000ffffULL, //64bit CS
		0x00cf92000000ffffULL  //64bit CS
	};

	memcpy(code_to_patch, (const void *)real_mode_code, (uint64_t)sizeof(real_mode_code));

	*((uint16_t *)(code_to_patch + REAL_MODE_STARTUP)) = (uint16_t)(ap_startup_pa>>4);
	*((uint16_t *)(code_to_patch + GDTR_OFFSET_IN_CODE)) = (uint16_t)(GDTR_OFFSET_IN_PAGE);
	*((uint32_t *)(code_to_patch + CPU_STARTUP32)) = (uint32_t)(uint64_t)(&ap_entry_32);

	memcpy(code_to_patch + GDT_OFFSET_IN_PAGE, (uint8_t *)(uint64_t)&gdt_32_table[0], sizeof(gdt_32_table));
	gdtr_32 = (gdtr32_t *)(code_to_patch + GDTR_OFFSET_IN_PAGE);
	gdtr_32->base = (uint32_t)((uint64_t)ap_startup_pa + GDT_OFFSET_IN_PAGE);
	gdtr_32->limit = sizeof(gdt_32_table) - 1;
}

void x86_mp_init(int cpu_num)
{
    TEE_Result ret;
    arch_flags_t flags = X86_MMU_PG_P | X86_MMU_PG_RW | X86_MMU_PG_PCD;

	ret = arch_mmu_map(AP_STARTUP_VADDR, AP_STARTUP_ADDR, PAGE_SIZE, flags);
	if (ret != TEE_SUCCESS) {
        EMSG("Failed to map SIPI page!\n");
        return;
    }

    setup_sipi_page(AP_STARTUP_VADDR, AP_STARTUP_ADDR);

    broadcast_init();
    wait_us(10000);
    broadcast_startup(AP_STARTUP_ADDR >> 12);

    while (optee_cpu_waken_up != cpu_num) {
        __asm__ __volatile__("pause":::"memory");
    }

    IMSG("All processors(%d) boot up now!\n", optee_cpu_waken_up);

    ret = arch_mmu_unmap(AP_STARTUP_VADDR, 1);
    if(ret != TEE_SUCCESS) {
        EMSG("Failed to unmap SIPI page!\n");
        return;
    }
}

