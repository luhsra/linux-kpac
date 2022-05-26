#include <linux/sched.h>
#include <linux/kthread.h>
#include <linux/freezer.h>
#include <linux/mm.h>
#include <linux/rmap.h>

#define PLAIN_MASK  0x0000FFFFFFFFFFFFUL
#define CIPHER_MASK 0xFFFF000000000000UL

enum {
    DEV_STANDBY = 0,
    DEV_PAC,
    DEV_AUT,
};

enum {
    PAC_STATE = 0,
    PAC_PLAIN,
    PAC_TWEAK,
    PAC_CIPH,
};

#define KPAC_CPU 3
#define KPAC_BASE 0xA000000UL
#define KPAC_VM_FLAGS \
	(VM_READ|VM_MAYREAD|VM_WRITE|VM_MAYWRITE|VM_MIXEDMAP|VM_SHARED)

static struct task_struct *kpacd_thread;
static DEFINE_MUTEX(kpacd_mutex);

static vm_fault_t kpac_fault(const struct vm_special_mapping *sm,
			     struct vm_area_struct *vma,
			     struct vm_fault *vmf)
{
	return VM_FAULT_SIGBUS;
}

static struct cpumask kpac_cpumask;
static struct page *kpac_pages[NR_CPUS];
static unsigned long *kpac_areas[NR_CPUS];
static const struct vm_special_mapping kpac_sm = {
	.name = "kpac",
	.fault = kpac_fault,
};

/*
 * Preallocate page tables for the specified user address.
 */
static int alloc_pgtables(struct mm_struct *mm, unsigned long addr)
{
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;

	pgd = pgd_offset(mm, addr);
	p4d = p4d_alloc(mm, pgd, addr);
	if (!p4d)
		return -ENOMEM;
	pud = pud_alloc(mm, p4d, addr);
	if (!pud)
		return -ENOMEM;
	pmd = pmd_alloc(mm, pud, addr);
	if (!pmd)
		return -ENOMEM;
	if (pte_alloc(mm, pmd))
		return -ENOMEM;

	return 0;
}

/**
 * kpac_migrate - Replace kpac page of the process on migration.
 */
void kpac_migrate(struct mm_struct *mm, int cpu)
{
	struct page *old_page = NULL;
	struct page *new_page = kpac_pages[cpu];
	pte_t *pte, entry;
	spinlock_t *ptl;

	if (!mm || !mm->kpac_vma) {
		trace_printk("kpac: no mm/vma\n");
		return;
	}

	BUG_ON(!new_page);

	get_page(new_page);
	pte = get_locked_pte(mm, KPAC_BASE, &ptl);

	entry = ptep_get_and_clear(mm, KPAC_BASE, pte);
	if (!pte_none(entry))
		old_page = pte_page(entry);
	else
		inc_mm_counter(mm, MM_FILEPAGES);

	page_add_file_rmap(new_page, false);
	entry = mk_pte(new_page, mm->kpac_vma->vm_page_prot);
	set_pte_at(mm, KPAC_BASE, pte, entry);

	pte_unmap_unlock(pte, ptl);

	if (old_page) {
		page_remove_rmap(old_page, false);
		put_page(old_page);
	}

	return;
}

/**
 * kpac_insert_vma - Prepare the process for kpac on startup.
 */
int kpac_insert_vma(struct mm_struct *mm)
{
	struct vm_area_struct *vma;
	int ret = 0;

	mmap_write_lock(mm);
	vma = _install_special_mapping(mm, KPAC_BASE, PAGE_SIZE, KPAC_VM_FLAGS,
				       &kpac_sm);
	if (IS_ERR(vma)) {
		 ret = PTR_ERR(vma);
		 goto out_unlock;
	}

	mm->kpac_vma = vma;

	/* Prepare page tables here so we can do page insertion during
	 * task migrations atomically. */
	ret = alloc_pgtables(mm, KPAC_BASE);
	if (ret)
		goto out_unlock;

	preempt_disable();
	kpac_migrate(mm, smp_processor_id());
	preempt_enable();

out_unlock:
	mmap_write_unlock(mm);
	return ret;
}

static void kpacd_poll(void)
{
	int cpu;

	for_each_cpu(cpu, &kpac_cpumask) {
		unsigned long *user, state;
		preempt_disable();
		user = kpac_areas[cpu];

		state = smp_load_acquire(&user[PAC_STATE]);
		if (state) {
			switch (state) {
			case DEV_PAC:
				user[PAC_CIPH] = user[PAC_PLAIN];
				trace_printk("#%d: [%lx %lx] -> %lx\n", cpu, user[1], user[2], user[3]);
				break;
			case DEV_AUT:
				user[PAC_PLAIN] = user[PAC_CIPH];
				trace_printk("#%d: %lx <- [%lx %lx]\n", cpu, user[1], user[2], user[3]);
				break;
			default:
				WARN_ON(1);
			}

			smp_store_release(&user[PAC_STATE], DEV_STANDBY);
		}
		preempt_enable();

		cpu_relax();
	}
}

static int kpacd(void *none)
{
	/* Get the max time-sharing priority */
	set_user_nice(current, MIN_NICE);

	/* Exclude our CPU from the cpumask */
	preempt_disable();
	cpumask_copy(&kpac_cpumask, cpu_online_mask);
	/* FIXME (kpac): make is_percpu_thread return true */
	cpumask_clear_cpu(smp_processor_id(), &kpac_cpumask);
	preempt_enable();

	while (!kthread_should_stop()) {
		kpacd_poll();
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
			pr_err("kpacd: kthread_run(kpacd) failed\n");
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

static int __init kpac_init(void)
{
	struct page *page;
	int cpu;

	for_each_present_cpu(cpu) {
		page = alloc_page(GFP_USER);
		if (!page)
			goto out_nomem;
		kpac_pages[cpu] = page;
		kpac_areas[cpu] = kmap(page);
		pr_info("kpac: allocated %lx for CPU%d\n", page_to_pfn(page), cpu);
	}

	return start_stop_kpacd();

out_nomem:
	for_each_present_cpu(cpu) {
		page = kpac_pages[cpu];
		kpac_pages[cpu] = NULL;
		kpac_areas[cpu] = NULL;
		if (page) {
			kunmap(page);
			put_page(page);
		}
	}

	return -ENOMEM;
}
late_initcall(kpac_init);
