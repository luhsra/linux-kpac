#include <linux/debugfs.h>
#include <linux/percpu-defs.h>
#include <linux/percpu.h>
#include <linux/sched.h>
#include <linux/kthread.h>
#include <linux/freezer.h>
#include <linux/mm.h>
#include <linux/rmap.h>
#include <linux/spinlock.h>
#include <linux/syscalls.h>

#include <linux/kpac.h>
#include <linux/kpac_backend.h>

#include <asm/pgalloc.h>

#define KPAC_BASE	CONFIG_KPAC_BASE
#define KPAC_VM_FLAGS	\
	(VM_READ|VM_MAYREAD|VM_WRITE|VM_MAYWRITE|VM_PFNMAP|VM_SHARED)

enum kpac_ops {
	OP_PAC = 1,
	OP_AUT = 2
};

static struct dentry *kpacd_dir; /* debugfs root */
static unsigned long kpac_base = CONFIG_KPAC_BASE; /* for debugfs */

static struct cpumask kpac_online_cpus;   /* Mask of currently polled cpus */
static DEFINE_SPINLOCK(kpac_online_lock); /* Protects kpac_online_cpus */

struct kpacd {
	struct cpumask	cpumask; /* Mask of CPUs this instance is polling */

	unsigned long 	nr_aut;  /* Statistics */
	unsigned long	nr_pac;

	struct task_struct	*kthread;
	unsigned int		cpu;	/* Which CPU does this instance
					 * belong to? */
};
static DEFINE_PER_CPU_ALIGNED(struct kpacd, kpacds);
static DEFINE_MUTEX(kpacd_lock); /* Protects kthreads and cpumasks of kpacds */

static vm_fault_t kpac_fault(const struct vm_special_mapping *sm,
			     struct vm_area_struct *vma,
			     struct vm_fault *vmf)
{
	/*
	 * A page fault should not happen for the kpac page.
	 */
	WARN_ON_ONCE(1);
	return VM_FAULT_SIGSEGV;
}

static const struct vm_special_mapping kpac_sm = {
	.name = "[kpac]",
	.fault = kpac_fault,
};

/*
 * Per-CPU pages for communication with userspace tasks.
 */
struct kpac_page {
	struct kpac_area	*area; /* Contents mapped in kernel */
	p4d_t			*p4d;  /* P4Ds for insertion in user pgds */
} ____cacheline_aligned;

static struct kpac_page kpac_pages[NR_CPUS] __ro_after_init;
static struct task_struct *kpac_task[NR_CPUS] __cacheline_aligned;

static bool kpac_initialized = false;

unsigned long kpac_pac(unsigned long plain, unsigned long tweak)
{
	struct task_struct *p = current;
	struct kpac_key *key = &p->kpac_context.key;

	long cipher = __kpac_pac(plain, tweak, key);
	this_cpu_inc(kpacds.nr_pac);
	/* trace_printk("sc: [%lx %lx] -> %lx\n", plain, tweak, cipher); */

	return cipher;
}

SYSCALL_DEFINE2(kpac_pac, long, plain, long, tweak)
{
	return kpac_pac(plain, tweak);
}

unsigned long kpac_aut(unsigned long cipher, unsigned long tweak)
{
	struct task_struct *p = current;
	struct kpac_key *key = &p->kpac_context.key;

	long plain = __kpac_aut(cipher, tweak, key);
	this_cpu_inc(kpacds.nr_aut);
	/* trace_printk("sc: %lx <- [%lx %lx]\n", plain, tweak, cipher); */

	return plain;
}

SYSCALL_DEFINE2(kpac_aut, long, cipher, long, tweak)
{
	return kpac_aut(cipher, tweak);
}

static inline void kpacd_poll_one(unsigned int cpu)
{
	struct kpac_area *area = kpac_pages[cpu].area;

	unsigned long state = smp_load_acquire(&area->status);
	if (state) {
		struct task_struct *p = kpac_task[cpu];
		struct kpac_key *key = &p->kpac_context.key;

		switch (state) {
		case OP_PAC:
			area->cipher = __kpac_pac(area->plain, area->tweak, key);
			this_cpu_inc(kpacds.nr_pac);
			/* trace_printk("#%u: [%lx %lx] -> %lx\n", cpu, */
			/* 	     area->plain, area->tweak, area->cipher); */
			break;
		case OP_AUT:
			area->plain = __kpac_aut(area->cipher, area->tweak, key);
			this_cpu_inc(kpacds.nr_aut);
			/* trace_printk("#%u: %lx <- [%lx %lx]\n", cpu, */
			/* 	     area->plain, area->tweak, area->cipher); */
			break;
		}

		smp_store_release(&area->status, 0);
	}
}

/**
 * kpac_finish - Finish a pending pointer authentication request in @current.
 */
void kpac_finish(void)
{
	unsigned int cpu;
	struct kpac_page *page;
	struct kpac_area *area;

	if (unlikely(!kpac_initialized))
		return;
	if (!current->mm)
		return;

	cpu = get_cpu();
	page = &kpac_pages[cpu];
	area = page->area;

	/*
	 * As long as kpac_online_lock is taken, threads cannot leave or return
	 * (see kpacd_enter() and kpacd_try_leave()).
	 *
	 * Let kpacd finish if it is active, i.e. the cpu is in the mask of
	 * polled cpus; otherwise, we complete the request ourselves.
	 */
	if (READ_ONCE(area->status)) {
		spin_lock_nested(&kpac_online_lock, SINGLE_DEPTH_NESTING);

		if (cpumask_test_cpu(cpu, &kpac_online_cpus))
			smp_cond_load_relaxed(&area->status, !VAL);
		else
			kpacd_poll_one(cpu);

		spin_unlock(&kpac_online_lock);
	}

	put_cpu();
}

/**
 * kpac_switch - Restore kpac context on task switch.
 * @next: Task being scheduled next.
 *
 * Store internal state of the device of @current task into the TCB and restore
 * saved context for the @next task.  Caller must hold the runqueue lock.
 */
void kpac_switch(struct task_struct *next)
{
	unsigned int cpu = smp_processor_id();
	struct task_struct *prev = current;
	struct kpac_page *page = &kpac_pages[cpu];
	struct kpac_area *area = page->area;

	if (unlikely(!kpac_initialized))
		return;

	if (prev->mm) {
		memcpy(&prev->kpac_context.area, area, sizeof(*area));
		WARN_ON(prev->kpac_context.area.status);
	}

	if (next->mm) {
		memcpy(area, &next->kpac_context.area, sizeof(*area));
		kpac_task[cpu] = next;
	}
}

bool vma_is_kpac_mapping(struct vm_area_struct *vma)
{
	return vma_is_special_mapping(vma, &kpac_sm);
}

/**
 * kpac_populate_pgds - Install kpac entries into the percpu page directories.
 * @mm: Address space to be populated.
 */
void kpac_populate_pgds(struct mm_struct *mm)
{
	unsigned int cpu;
	for_each_present_cpu(cpu) {
		pgd_t *pgd = pgd_offset_cpu(mm, cpu, KPAC_BASE);
		p4d_t *p4d = kpac_pages[cpu].p4d;
		pgd_populate_one(mm, pgd, p4d);
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
	 * and fail everyone who insists on using it.
	 */
	vma = _install_special_mapping(mm, KPAC_BASE & PGDIR_MASK, PGDIR_SIZE,
				       KPAC_VM_FLAGS, &kpac_sm);
	if (IS_ERR(vma)) {
		ret = PTR_ERR(vma);
		goto out_unlock;
	}

	kpac_populate_pgds(mm);

	memset(&current->kpac_context, 0, sizeof(current->kpac_context));
	__kpac_reset_key(&current->kpac_context.key);

out_unlock:
	mmap_write_unlock(mm);
	return ret;
}

/*
 * Try to stop the kpacd thread, failing if there's a waiter in kpac_finish().
 * On success removes cpus polled by this thread from online mask.
 */
static inline int kpacd_try_leave(void)
{
	int ret = spin_trylock(&kpac_online_lock);
	if (ret) {
		cpumask_andnot(&kpac_online_cpus,
			       &kpac_online_cpus, this_cpu_ptr(&kpacds.cpumask));
		spin_unlock(&kpac_online_lock);
		preempt_enable_no_resched();
	}

	/* If we had no luck with trylock, try again after polling. */
	return ret;
}

/*
 * Mark the CPUs polled by this kpacd thread as online.
 */
static inline void kpacd_enter(void)
{
	preempt_disable();
	spin_lock(&kpac_online_lock);
	cpumask_or(&kpac_online_cpus,
		   &kpac_online_cpus, this_cpu_ptr(&kpacds.cpumask));
	spin_unlock(&kpac_online_lock);
}

/*
 * The entry point of kpacd.
 */
static int kpacd_main(void *none)
{
	unsigned int cpu;

	/* Get the max time-sharing priority */
	set_user_nice(current, MIN_NICE);

	kpacd_enter();
	for (;;) {
		if (need_resched() || kthread_should_stop()) {
			if (kpacd_try_leave()) {
				if (kthread_should_stop())
					goto out;
				cond_resched();

				kpacd_enter();
			}
		}

		for_each_cpu(cpu, this_cpu_ptr(&kpacds.cpumask))
			kpacd_poll_one(cpu);

		cpu_relax();
	}

out:
	return 0;
}

/*
 * Start a new kpacd instance.  Caller must hold p->lock.
 */
static int start_kpacd(struct kpacd *p)
{
	struct task_struct *kthread;

	if (p->kthread || cpumask_empty(&p->cpumask))
		return 0;

	kthread = kthread_run_on_cpu(kpacd_main, NULL, p->cpu, "kpacd/%u");
	if (IS_ERR(kthread)) {
		pr_err("kpacd/%u: kthread_run failed: %pe\n", p->cpu, kthread);
		return PTR_ERR(kthread);
	}

	p->kthread = kthread;

	return 0;
}

/*
 * Stop kpacd instance.  Caller must hold p->lock.
 */
static void stop_kpacd(struct kpacd *p)
{
	if (p->kthread) {
		kthread_stop(p->kthread);
		p->kthread = NULL;
	}
}

/*
 * Create p4d and the underlying page tables and install a single pfn there.
 */
static p4d_t *kpac_alloc_pgtables(unsigned long addr, unsigned long pfn)
{
	p4d_t *p4dp __maybe_unused;
	pud_t *pudp;
	pmd_t *pmdp;
	pte_t *ptep, pte;
	pgtable_t pte_page;

	pte = pfn_pte(pfn, vm_get_page_prot(KPAC_VM_FLAGS));
	pte = pte_mkwrite(pte); /* Inhibit page faults due to software dirty
				 * accounting. */

	pte_page = pte_alloc_one(NULL);
	if (!pte_page)
		goto out_nopte;
	ptep = page_address(pte_page);
	set_pte(ptep+pte_index(addr), pte);

	pmdp = pmd_alloc_one(NULL, addr);
	if (!pmdp)
		goto out_nopmd;
	pmd_populate(NULL, pmdp+pmd_index(addr), pte_page);

	pudp = pud_alloc_one(NULL, addr);
	if (!pudp)
		goto out_nopud;
	pud_populate(NULL, pudp+pud_index(addr), pmdp);

	if (mm_p4d_folded(&init_mm))
		return (p4d_t *) pudp;

#ifdef __PAGETABLE_P4D_FOLDED
	BUG();
#else
	p4dp = p4d_alloc_one(NULL, addr);
	if (!p4dp)
		goto out_nop4d;
	p4d_populate(NULL, p4dp+p4d_index(addr), pudp);

	return p4dp;

out_nop4d:
	pud_free(NULL, pudp);
#endif
out_nopud:
	pmd_free(NULL, pmdp);
out_nopmd:
	pte_free(NULL, pte_page);
out_nopte:
	return NULL;
}

static void kpac_free_pgtables(p4d_t *p4d, unsigned long addr)
{
	pud_t *pud;
	pmd_t *pmd;
	pgtable_t pte;

	if (mm_p4d_folded(&init_mm)) {
		pud = (pud_t *) p4d;
	} else {
#ifdef __PAGETABLE_P4D_FOLDED
		BUG();
#else
		pud = p4d_pgtable(*(p4d + p4d_index(addr)));
		p4d_free(NULL, p4d);
#endif
	}

	pmd = pud_pgtable(*(pud + pud_index(addr)));
	pud_free(NULL, pud);

	pte = pmd_page(*(pmd + pmd_index(addr)));
	pmd_free(NULL, pmd);
	pte_free(NULL, pte);
}

static int kpacd_cpumask_show(struct seq_file *m, void *v)
{
	struct kpacd *kpacd = (struct kpacd *) m->private;
	mutex_lock(&kpacd_lock);
	seq_printf(m, "%*pbl\n", cpumask_pr_args(&kpacd->cpumask));
	mutex_unlock(&kpacd_lock);
	return 0;
}

static int kpacd_validate_cpumask(struct kpacd *kpacd, struct cpumask *mask)
{
	unsigned int cpu;

	if (cpumask_test_cpu(kpacd->cpu, mask)) {
		pr_err("kpacd/%u: cpumask includes the hosting cpu\n",
		       kpacd->cpu);
		return -EINVAL;
	}

	for_each_present_cpu(cpu) {
		struct kpacd *kpacd_cursor = per_cpu_ptr(&kpacds, cpu);
		if (kpacd_cursor != kpacd &&
		    cpumask_intersects(&kpacd_cursor->cpumask, mask)) {
			pr_err("kpacd/%u: cpumask intersects with kpacd/%u\n",
			       kpacd->cpu, cpu);

			return -EINVAL;
		}
	}

	return 0;
}

static ssize_t kpacd_cpumask_write(struct file *file,
				   const char __user *user_buf,
				   size_t count, loff_t *ppos)
{
	struct seq_file *s = (struct seq_file *) file->private_data;
	struct kpacd *kpacd = (struct kpacd *) s->private;
	struct cpumask mask;
	int err = 0;

	mutex_lock(&kpacd_lock);
	stop_kpacd(kpacd);

	err = cpumask_parselist_user(user_buf, count, &mask);
	if (err)
		goto err_unlock;

	err = kpacd_validate_cpumask(kpacd, &mask);
	if (err)
		goto err_unlock;

	cpumask_copy(&kpacd->cpumask, &mask);
	err = start_kpacd(kpacd);
	if (err)
		goto err_unlock;

	mutex_unlock(&kpacd_lock);
	return count;

err_unlock:
	/* Clear the cpumask because the thread did not start */
	cpumask_clear(&kpacd->cpumask);
	mutex_unlock(&kpacd_lock);
	return err;
}

static int kpacd_cpumask_open(struct inode *inode, struct file *file)
{
	return single_open(file, kpacd_cpumask_show, inode->i_private);
}

static struct file_operations kpacd_cpumask_fops = {
	.open		= kpacd_cpumask_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
	.write		= kpacd_cpumask_write
};

static int per_cpu_ulong_get(void *data, u64 *val)
{
	unsigned long acc = 0;
	unsigned int cpu;

	for_each_present_cpu(cpu)
		acc += *per_cpu_ptr((unsigned long *) data, cpu);

	*val = acc;
	return 0;
}

DEFINE_DEBUGFS_ATTRIBUTE(per_cpu_ulong_fops, per_cpu_ulong_get, NULL, "%llu\n");

/*
 * Create a file tree in debugfs to manage pointer authentication daemons from
 * userspace.
 */
static int __init kpac_init_debugfs(void)
{
	struct dentry *ret;
	unsigned int cpu;

	kpacd_dir = debugfs_create_dir("kpacd", NULL);
	if (IS_ERR(kpacd_dir))
		return PTR_ERR(kpacd_dir);

	for_each_present_cpu(cpu) {
		struct kpacd *kpacd = per_cpu_ptr(&kpacds, cpu);
		struct dentry *dir;
		char buf[16];

		snprintf(buf, sizeof(buf), "%u", cpu);
		ret = dir = debugfs_create_dir(buf, kpacd_dir);
		if (IS_ERR(ret))
			goto out_remove;

		/* Mask of the cpus polled */
		ret = debugfs_create_file("cpumask", 0644, dir, kpacd,
					  &kpacd_cpumask_fops);
		if (IS_ERR(ret))
			goto out_remove;
	}

	/* Read only statistics */
	debugfs_create_xul("addr", 0444, kpacd_dir, &kpac_base);
	debugfs_create_file_unsafe("nr_pac", 0444, kpacd_dir,
				   &kpacds.nr_pac, &per_cpu_ulong_fops);
	debugfs_create_file_unsafe("nr_aut", 0444, kpacd_dir,
				   &kpacds.nr_aut, &per_cpu_ulong_fops);
	debugfs_create_str("backend", 0444, kpacd_dir,
			   (char **) &kpac_backend_name);

	return 0;

out_remove:
	debugfs_remove(kpacd_dir);
	return PTR_ERR(ret);
}

static void *get_zeroed_page_cpu(gfp_t gfp_mask, unsigned int cpu)
{
	struct page *page;

	gfp_mask |= __GFP_ZERO;
	gfp_mask &= ~__GFP_HIGHMEM;

	page = __alloc_pages(gfp_mask, 0, cpu_to_node(cpu), NULL);
	return page_address(page);
}

/*
 * Allocate communication pages and corresponding p4d pgtables.
 */
static int __init kpac_init_pages(void)
{
	unsigned int cpu;

	for_each_present_cpu(cpu) {
		struct kpac_area *area;
		unsigned long pfn;
		p4d_t *p4d;

		area = (struct kpac_area *) get_zeroed_page_cpu(GFP_USER, cpu);
		if (!area)
			goto out_nomem;
		pfn = PHYS_PFN(__pa(area));
		p4d = kpac_alloc_pgtables(KPAC_BASE, pfn);
		kpac_pages[cpu].area = area;
		kpac_pages[cpu].p4d = p4d;

		pr_info("kpac: allocated %lx for CPU%u\n", pfn, cpu);
	}

	return 0;

out_nomem:
	for_each_present_cpu(cpu) {
		struct kpac_page *page = &kpac_pages[cpu];
		if (page->p4d)
			kpac_free_pgtables(page->p4d, KPAC_BASE);
		if (page->area)
			free_page((unsigned long) page->area);
	}

	return -ENOMEM;
}

/*
 * Initialize context for per-CPU instances.
 */
static int __init kpac_init_kpacds(void)
{
	unsigned int cpu;
	for_each_present_cpu(cpu)
		per_cpu(kpacds.cpu, cpu) = cpu;

	return 0;
}

/*
 * Initialize the infrastructure required by the device instances and user
 * tasks.
 */
static int __init kpac_init(void)
{
	int ret;

	ret = kpac_init_pages();
	if (ret)
		goto fail;

	ret = kpac_init_kpacds();
	if (ret)
		goto fail;

	ret = kpac_init_debugfs();
	if (ret)
		WARN_ON(1);

	smp_store_release(&kpac_initialized, true);
	return 0;

fail:
	pr_err("kpac: initialization failed\n");

	return ret;
}
late_initcall(kpac_init);
