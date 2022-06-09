#ifndef _LINUX_KPAC_H
#define _LINUX_KPAC_H

#include <linux/mm_types.h>

enum kpac_regs {
	KPAC_STATE = 0,
	KPAC_PLAIN,
	KPAC_TWEAK,
	KPAC_CIPHER,
	KPAC_NREGS
};

/* Context of the device saved in the TCB */
struct kpac_context {
	unsigned long regs[KPAC_NREGS];
};

bool vma_is_kpac_mapping(struct vm_area_struct *vma);
void kpac_populate_pgds(struct mm_struct *mm);
void kpac_switch(struct task_struct *p);
void kpac_migrate(struct task_struct *p, int cpu);
int kpac_exec(void);

#endif	/* _LINUX_KPAC_H */
