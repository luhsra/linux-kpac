// SPDX-License-Identifier: GPL-2.0-only
/*
 * PGD allocation/freeing
 *
 * Copyright (C) 2012 ARM Ltd.
 * Author: Catalin Marinas <catalin.marinas@arm.com>
 */

#include <linux/mm.h>
#include <linux/gfp.h>
#include <linux/highmem.h>
#include <linux/slab.h>

#include <asm/pgalloc.h>
#include <asm/page.h>
#include <asm/tlbflush.h>

static struct kmem_cache *pgd_cache __ro_after_init;

static pgd_t *_pgd_alloc(void)
{
	gfp_t gfp = GFP_PGTABLE_USER;

	if (PGD_SIZE == PAGE_SIZE)
		return (pgd_t *)__get_free_page(gfp);
	else
		return kmem_cache_alloc(pgd_cache, gfp);
}

static void _pgd_free(pgd_t *pgd)
{
	if (PGD_SIZE == PAGE_SIZE)
		free_page((unsigned long)pgd);
	else
		kmem_cache_free(pgd_cache, pgd);
}

pgd_t *pgd_alloc(struct mm_struct *mm)
{
	int cpu;

	mm->pgd = _pgd_alloc();

	if (!mm->pgd)
		goto out;

	for_each_present_cpu(cpu) {
		mm->pcpu_pgds[cpu] = _pgd_alloc();
		if (!mm->pcpu_pgds[cpu])
			goto out_free_pgd;
	}

	return mm->pgd;

out_free_pgd:
	for_each_present_cpu(cpu) {
		if (mm->pcpu_pgds[cpu])
			_pgd_free(mm->pcpu_pgds[cpu]);
		mm->pcpu_pgds[cpu] = NULL;
	}
	_pgd_free(mm->pgd);
	mm->pgd = NULL;

out:
	return NULL;
}

void pgd_free(struct mm_struct *mm, pgd_t *pgd)
{
	int cpu;

	for_each_present_cpu(cpu) {
		if (mm->pcpu_pgds[cpu])
			_pgd_free(mm->pcpu_pgds[cpu]);
		mm->pcpu_pgds[cpu] = NULL;
	}

	_pgd_free(mm->pgd);
	mm->pgd = NULL;
}

void __init pgtable_cache_init(void)
{
	if (PGD_SIZE == PAGE_SIZE)
		return;

#ifdef CONFIG_ARM64_PA_BITS_52
	/*
	 * With 52-bit physical addresses, the architecture requires the
	 * top-level table to be aligned to at least 64 bytes.
	 */
	BUILD_BUG_ON(PGD_SIZE < 64);
#endif

	/*
	 * Naturally aligned pgds required by the architecture.
	 */
	pgd_cache = kmem_cache_create("pgd_cache", PGD_SIZE, PGD_SIZE,
				      SLAB_PANIC, NULL);
}
