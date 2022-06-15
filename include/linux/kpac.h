#ifndef _LINUX_KPAC_H
#define _LINUX_KPAC_H

#include <linux/mm_types.h>
#include <linux/kpac_types.h>

bool vma_is_kpac_mapping(struct vm_area_struct *vma);
void kpac_populate_pgds(struct mm_struct *mm);
void kpac_switch(struct task_struct *p);
int kpac_exec(void);

#endif	/* _LINUX_KPAC_H */
