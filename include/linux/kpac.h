#ifndef _LINUX_KPAC_H
#define _LINUX_KPAC_H

#include <linux/mm_types.h>
#include <linux/kpac_types.h>

#ifdef CONFIG_KPAC

bool vma_is_kpac_mapping(struct vm_area_struct *vma);
void kpac_populate_pgds(struct mm_struct *mm);
void kpac_switch(struct task_struct *p);
int kpac_exec(void);

#else /* CONFIG_KPAC */

static inline bool vma_is_kpac_mapping(struct vm_area_struct *vma)
{
	return false;
}

static inline void kpac_populate_pgds(struct mm_struct *mm)
{
	BUG();
}

static inline void kpac_switch(struct task_struct *p)
{
	return;
}

static inline int kpac_exec(void)
{
	return 0;
}

#endif /* CONFIG_KPAC */

#endif /* _LINUX_KPAC_H */
