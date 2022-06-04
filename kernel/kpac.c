#include <linux/sched.h>
#include <linux/kthread.h>
#include <linux/freezer.h>
#include <linux/mm.h>
#include <linux/rmap.h>
#include <asm/pgalloc.h>

#define KPAC_CPU	3
#define KPAC_BASE	0x9AC00000000		/* Occupies it's own pgd. */
#define KPAC_VM_FLAGS	\
	(VM_READ|VM_MAYREAD|VM_WRITE|VM_MAYWRITE|VM_PFNMAP|VM_SHARED)

enum kpac_ops {
	OP_PAC = 1,
	OP_AUT = 2
};

static bool kpac_initialized = false;

static struct task_struct *kpacd_thread;
static DEFINE_MUTEX(kpacd_mutex);

static vm_fault_t kpac_fault(const struct vm_special_mapping *sm,
			     struct vm_area_struct *vma,
			     struct vm_fault *vmf)
{
	WARN_ON_ONCE(1);
	return VM_FAULT_SIGSEGV;
}

static const struct vm_special_mapping kpac_sm = {
	.name = "[kpac]",
	.fault = kpac_fault,
};

static unsigned long *kpac_areas[NR_CPUS];
static p4d_t *kpac_p4ds[NR_CPUS];

/**
 * kpac_switch - Restore kpac context on task switch.
 * @next: Task being scheduled next.
 *
 * Store internal state of the device of @current task into the TCB and restore
 * saved context for the @next task.
 */
void kpac_switch(struct task_struct *next)
{
	int cpu = smp_processor_id();
	struct task_struct *prev = current;
	unsigned long *area = kpac_areas[cpu];

	if (unlikely(!kpac_initialized))
		return;

	/* Let the kpacd thread finish authentication. */
	while (smp_load_acquire(&area[0]))
		cpu_relax();

	if (prev->mm) {
		unsigned long *dst = prev->kpac_context.regs;
		memcpy(dst, area, sizeof(*dst) * KPAC_NREGS);
	}
	if (next->mm) {
		unsigned long *src = next->kpac_context.regs;
		memcpy(area, src, sizeof(*src) * KPAC_NREGS);
	}
}

bool vma_is_kpac_mapping(struct vm_area_struct *vma)
{
	return vma_is_special_mapping(vma, &kpac_sm);
}

/**
 * kpac_install_pgds - Install kpac entries into the percpu page directories.
 * @mm: Address space to be populated.
 */
void kpac_install_pgds(struct mm_struct *mm)
{
	int cpu;
	for_each_present_cpu(cpu) {
		pgd_t *pgd = pgd_offset_cpu(mm, cpu, KPAC_BASE);
		p4d_t *p4d = kpac_p4ds[cpu];
		set_pgd(pgd, __pgd(_PAGE_TABLE | __pa(p4d)));
	}
}

/**
 * kpac_exec - Prepare kpac mapping on process startup.
 */
int kpac_exec(void)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	int ret = 0;

	if (unlikely(!kpac_initialized))
		return 0;

	mmap_write_lock(mm);
	/*
	 * Reserve the whole PGD range to avoid conflicts with other mappings
	 * and complain loudly in case someone insists on using this area.
	 */
	vma = _install_special_mapping(mm, KPAC_BASE & PGDIR_MASK, PGDIR_SIZE,
				       KPAC_VM_FLAGS, &kpac_sm);
	if (IS_ERR(vma)) {
		ret = PTR_ERR(vma);
		goto out_unlock;
	}

	kpac_install_pgds(mm);

	memset(&current->kpac_context, 0, sizeof(current->kpac_context));

out_unlock:
	mmap_write_unlock(mm);
	return ret;
}

static void kpacd_poll(struct cpumask *cpumask)
{
	int cpu;

	for_each_cpu(cpu, cpumask) {
		unsigned long *user, state;
		preempt_disable();
		user = kpac_areas[cpu];

		state = smp_load_acquire(&user[KPAC_STATE]);
		if (state) {
			switch (state) {
			case OP_PAC:
				user[KPAC_CIPHER] = user[KPAC_PLAIN];
				trace_printk("#%d: [%lx %lx] -> %lx\n", cpu, user[1], user[2], user[3]);
				break;
			case OP_AUT:
				user[KPAC_PLAIN] = user[KPAC_CIPHER];
				trace_printk("#%d: %lx <- [%lx %lx]\n", cpu, user[1], user[2], user[3]);
				break;
			}

			smp_store_release(&user[KPAC_STATE], 0);
		}
		preempt_enable();

		cpu_relax();
	}
}

static int kpacd(void *none)
{
	struct cpumask cpumask;

	/* Get the max time-sharing priority */
	set_user_nice(current, MIN_NICE);

	/* Exclude our CPU from the cpumask */
	cpumask_copy(&cpumask, cpu_online_mask);
	cpumask_clear_cpu(smp_processor_id(), &cpumask);

	while (!kthread_should_stop()) {
		kpacd_poll(&cpumask);
		cond_resched();
	}

	return 0;
}

static int start_stop_kpacd(void)
{
	int err = 0;

	mutex_lock(&kpacd_mutex);
	if (!kpacd_thread) {
		kpacd_thread = kthread_run_on_cpu(kpacd, NULL, KPAC_CPU, "kpacd");

		if (IS_ERR(kpacd_thread)) {
			pr_err("kpac: kthread_run(kpacd) failed\n");
			err = PTR_ERR(kpacd_thread);
			kpacd_thread = NULL;
			goto fail;
		}
	} else {
		kthread_stop(kpacd_thread);
		kpacd_thread = NULL;
	}

fail:
	mutex_unlock(&kpacd_mutex);
	return err;
}

/*
 * Create p4d and the underlying page tables and install a single pfn there.
 */
static p4d_t *kpac_alloc_pgtables(unsigned long addr, unsigned long pfn,
				  pgprot_t pgprot)
{
	p4d_t p4d, *p4dp;
	pud_t pud, *pudp;
	pmd_t pmd, *pmdp;
	pte_t pte, *ptep;

	ptep = pte_alloc_one_kernel(&init_mm);
	if (!ptep)
		goto out_nopte;
	pte = pfn_pte(pfn, pgprot);
	set_pte(ptep+pte_index(addr), pte);

	pmdp = pmd_alloc_one(&init_mm, addr);
	if (!pmdp)
		goto out_nopmd;
	pmd = __pmd(_PAGE_TABLE | __pa(ptep));
	set_pmd(pmdp+pmd_index(addr), pmd);

	pudp = pud_alloc_one(&init_mm, addr);
	if (!pudp)
		goto out_nopud;
	pud = __pud(_PAGE_TABLE | __pa(pmdp));
	set_pud(pudp+pud_index(addr), pud);

	if (mm_p4d_folded(&init_mm))
		return (p4d_t *) pudp;

	p4dp = p4d_alloc_one(&init_mm, addr);
	if (!p4dp)
		goto out_nop4d;
	p4d = __p4d(_PAGE_TABLE | __pa(pudp));
	set_p4d(p4dp+p4d_index(addr), p4d);

	return p4dp;

out_nop4d:
	pud_free(&init_mm, pudp);
out_nopud:
	pmd_free(&init_mm, pmdp);
out_nopmd:
	pte_free_kernel(&init_mm, ptep);
out_nopte:
	return NULL;
}

static void kpac_free_pgtables(p4d_t *p4d, unsigned long addr)
{
	pud_t *pud = mm_p4d_folded(&init_mm)
		? (pud_t *) p4d
		: p4d_pgtable(*(p4d + p4d_index(addr)));
	pmd_t *pmd = pud_pgtable(*(pud + pud_index(addr)));
	pte_t *pte = (pte_t *) pmd_page_vaddr(*(pmd + pmd_index(addr)));

	p4d_free(&init_mm, p4d);
	pud_free(&init_mm, pud);
	pmd_free(&init_mm, pmd);
	pte_free_kernel(&init_mm, pte);
}

static int __init kpac_init(void)
{
	int cpu;

	for_each_present_cpu(cpu) {
		unsigned long *area, pfn;
		area = (unsigned long *) get_zeroed_page(GFP_USER);
		if (!area)
			goto out_nomem;
		pfn = PHYS_PFN(__pa(area));
		kpac_p4ds[cpu] = kpac_alloc_pgtables(KPAC_BASE, pfn,
						     vm_get_page_prot(KPAC_VM_FLAGS));
		kpac_areas[cpu] = area;
		pr_info("kpac: allocated %lx for CPU%d\n", pfn, cpu);
	}

	smp_store_release(&kpac_initialized, true);
	return start_stop_kpacd();

out_nomem:
	for_each_present_cpu(cpu) {
		unsigned long *area = kpac_areas[cpu];
		p4d_t *p4d = kpac_p4ds[cpu];

		kpac_p4ds[cpu] = NULL;
		kpac_areas[cpu] = NULL;

		if (p4d)
			kpac_free_pgtables(p4d, KPAC_BASE);
		if (area)
			free_page((unsigned long) area);
	}

	pr_err("kpac: initialization failed\n");

	return -ENOMEM;
}
late_initcall(kpac_init);
