#include <linux/sched.h>
#include <linux/kthread.h>
#include <linux/freezer.h>
#include <linux/mm.h>
#include <linux/rmap.h>

#include <linux/kpac.h>
#include <linux/kpac_backend.h>

#include <asm/pgalloc.h>

#define KPAC_CPU	3
#define KPAC_BASE	CONFIG_KPAC_BASE	/* Occupies it's own pgd. */
#define KPAC_VM_FLAGS	\
	(VM_READ|VM_MAYREAD|VM_WRITE|VM_MAYWRITE|VM_PFNMAP|VM_SHARED)

enum kpac_ops {
	OP_PAC = 1,
	OP_AUT = 2
};

static struct kobject *kpac_kobj; /* The parent directory hosting the device
				   * instances */
static bool kpac_initialized;     /* Forbid access to uninitialized state */

struct kpacd {
	struct kobject		kobj;
	struct task_struct	*kthread;

	struct cpumask		cpumask; /* Mask of CPUs we are polling */

	struct {
		unsigned long 	nr_aut;
		unsigned long	nr_pac;
	} stat;

	struct list_head	node;
};
static LIST_HEAD(kpacd_list);
static DEFINE_MUTEX(kpacd_mutex);

#define to_kpacd(kobj)		container_of(kobj, struct kpacd, kobj)

static ssize_t kpacd_stat_show(struct kobject *kobj, struct kobj_attribute *attr,
			       char *buf)
{
	struct kpacd *kpacd = to_kpacd(kobj);
	unsigned long var;

	if (!strcmp(attr->attr.name, "nr_pac"))
		var = READ_ONCE(kpacd->stat.nr_pac);
	else if (!strcmp(attr->attr.name, "nr_aut"))
		var = READ_ONCE(kpacd->stat.nr_aut);
	else
		BUG();

	return sysfs_emit(buf, "%lu\n", var);
}

static ssize_t kpacd_stat_store(struct kobject *kobj, struct kobj_attribute *attr,
				const char *buf, size_t count)
{
	struct kpacd *kpacd = to_kpacd(kobj);

	/* FIXME (kpac): racing with kpacd_poll here */

	if (!strcmp(attr->attr.name, "nr_pac"))
		WRITE_ONCE(kpacd->stat.nr_pac, 0);
	else if (!strcmp(attr->attr.name, "nr_aut"))
		WRITE_ONCE(kpacd->stat.nr_aut, 0);
	else
		return -ENOENT;

	return count;
}

/* Expose some statistics through sysfs: */
static struct kobj_attribute nr_pac_attribute =
	__ATTR(nr_pac, 0644, kpacd_stat_show, kpacd_stat_store);
static struct kobj_attribute nr_aut_attribute =
	__ATTR(nr_aut, 0644, kpacd_stat_show, kpacd_stat_store);

static struct attribute *kpacd_default_attrs[] = {
	&nr_pac_attribute.attr,
	&nr_aut_attribute.attr,
	NULL,
};
ATTRIBUTE_GROUPS(kpacd_default);

static void kpacd_release(struct kobject *kobj)
{
	struct kpacd *kpacd = to_kpacd(kobj);
	kfree(kpacd);
}

static struct kobj_type kpacd_ktype = {
	.release	= kpacd_release,
	.sysfs_ops	= &kobj_sysfs_ops,
	.default_groups	= kpacd_default_groups
};

static vm_fault_t kpac_fault(const struct vm_special_mapping *sm,
			     struct vm_area_struct *vma,
			     struct vm_fault *vmf)
{
	/* A page fault should not happen for the kpac page.  If it does, kill
	 * the task and report the problem. */
	WARN_ON_ONCE(1);
	return VM_FAULT_SIGSEGV;
}

static const struct vm_special_mapping kpac_sm = {
	.name = "[kpac]",
	.fault = kpac_fault,
};

/* Per-CPU pages for communication with userspace tasks. */
struct kpac_page {
	/* Contents mapped in kernel: */
	struct kpac_area	*area ____cacheline_aligned;

	/* Task currently associated with this page: */
	struct task_struct	*task;

	/* P4Ds for insertion in userspace pgds: */
	p4d_t			*p4d;
};
static struct kpac_page kpac_pages[NR_CPUS] __cacheline_aligned;

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
	struct kpac_page *page = &kpac_pages[cpu];
	struct kpac_area *area = page->area;

	if (unlikely(!kpac_initialized))
		return;

	/* Let the kpacd thread finish authentication. */
	while (smp_load_acquire(&area->status))
		cpu_relax();

	if (prev->mm) {
		struct kpac_area *dst = &prev->kpac_context.area;
		memcpy(dst, area, sizeof(*dst));
	}
	if (next->mm) {
		struct kpac_area *src = &next->kpac_context.area;
		memcpy(area, src, sizeof(*src));
	}

	page->task = next;
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
	int cpu;
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
	 * and complain loudly in case someone insists on using this area.
	 */
	vma = _install_special_mapping(mm, KPAC_BASE & PGDIR_MASK, PGDIR_SIZE,
				       KPAC_VM_FLAGS, &kpac_sm);
	if (IS_ERR(vma)) {
		ret = PTR_ERR(vma);
		goto out_unlock;
	}

	kpac_populate_pgds(mm);

	memset(&current->kpac_context, 0, sizeof(current->kpac_context));
	kpac_reset_key(&current->kpac_context.key);

out_unlock:
	mmap_write_unlock(mm);
	return ret;
}

static inline void kpacd_poll_one(struct kpacd *kpacd, int cpu)
{
	struct kpac_area *area = kpac_pages[cpu].area;

	unsigned long state = smp_load_acquire(&area->status);
	if (state) {
		struct task_struct *p = kpac_pages[cpu].task;
		struct kpac_key *key = &p->kpac_context.key;

		switch (state) {
		case OP_PAC:
			area->cipher = kpac_pac(area->plain, area->tweak, key);
			kpacd->stat.nr_pac++;
			/* trace_printk("#%d: [%lx %lx] -> %lx\n", cpu, */
			/* 	     area->plain, area->tweak, area->cipher); */
			break;
		case OP_AUT:
			area->plain = kpac_aut(area->cipher, area->tweak, key);
			kpacd->stat.nr_aut++;
			/* trace_printk("#%d: %lx <- [%lx %lx]\n", cpu, */
			/* 	     area->plain, area->tweak, area->cipher); */
			break;
		}

		smp_store_release(&area->status, 0);
	}

	cpu_relax();
}

static inline void kpacd_poll(struct kpacd *kpacd)
{
	int cpu;

	preempt_disable();
	for_each_cpu(cpu, &kpacd->cpumask)
		kpacd_poll_one(kpacd, cpu);

	preempt_enable_no_resched();
}

/*
 * The entry point of kpacd
 */
static int kpacd_main(void *__kpacd)
{
	struct kpacd *kpacd = (struct kpacd *) __kpacd;
	if (kthread_should_stop())
		return 0;

	/* Get the max time-sharing priority */
	set_user_nice(current, MIN_NICE);

	/* Exclude our CPU from the cpumask */
	cpumask_copy(&kpacd->cpumask, cpu_online_mask);
	cpumask_clear_cpu(smp_processor_id(), &kpacd->cpumask);

	while (!kthread_should_stop()) {
		if (need_resched())
			cond_resched();

		kpacd_poll(kpacd);
	}

	kobject_put(&kpacd->kobj);

	return 0;
}

/*
 * Start a new kpacd instance.
 */
static int start_new_kpacd(void)
{
	int ret = 0;
	struct kpacd *p = kzalloc(sizeof(*p), GFP_KERNEL);
	if (!p)
		return -ENOMEM;

	mutex_lock(&kpacd_mutex);

	p->kthread = kthread_create_on_cpu(kpacd_main, p, KPAC_CPU, "kpacd");
	if (IS_ERR(p->kthread)) {
		pr_err("kpac: kthread_create(kpacd) failed\n");
		ret = PTR_ERR(p->kthread);
		goto out_free;
	}

	ret = kobject_init_and_add(&p->kobj, &kpacd_ktype, kpac_kobj,
				   "kpacd-%d", task_pid_nr(p->kthread));
	if (ret)
		goto out_stop;
	kobject_uevent(&p->kobj, KOBJ_ADD);
	wake_up_process(p->kthread);

	list_add(&p->node, &kpacd_list);

	mutex_unlock(&kpacd_mutex);
	return 0;

out_stop:
	kthread_stop(p->kthread);
out_free:
	kfree(p);
	mutex_unlock(&kpacd_mutex);
	return ret;
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

/*
 * Initialize the infrastructure required by the device instances and user
 * tasks.
 */
static int __init kpac_init(void)
{
	int ret = -ENOMEM;
	int cpu;

	for_each_present_cpu(cpu) {
		struct kpac_area *area;
		unsigned long pfn;
		p4d_t *p4d;

		area = (struct kpac_area *) get_zeroed_page(GFP_USER);
		if (!area)
			goto out_nomem;
		pfn = PHYS_PFN(__pa(area));
		p4d = kpac_alloc_pgtables(KPAC_BASE, pfn);

		kpac_pages[cpu].area = area;
		kpac_pages[cpu].p4d = p4d;

		pr_info("kpac: allocated %lx for CPU%d\n", pfn, cpu);
	}

	kpac_kobj = kobject_create_and_add("kpac", kernel_kobj);
	if (IS_ERR(kpac_kobj)) {
		ret = PTR_ERR(kpac_kobj);
		goto out_nomem;
	}

	smp_store_release(&kpac_initialized, true);
	return start_new_kpacd();

out_nomem:
	for_each_present_cpu(cpu) {
		struct kpac_page *page = &kpac_pages[cpu];
		if (page->p4d)
			kpac_free_pgtables(page->p4d, KPAC_BASE);
		if (page->area)
			free_page((unsigned long) page->area);
	}

	pr_err("kpac: initialization failed\n");

	return ret;
}
late_initcall(kpac_init);
