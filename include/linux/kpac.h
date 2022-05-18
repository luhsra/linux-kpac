#ifndef _LINUX_KPAC_H
#define _LINUX_KPAC_H

#include <linux/mm.h>

void kpac_migrate(struct mm_struct *, int);
int kpac_insert_vma(struct mm_struct *);

#endif	/* _LINUX_KPAC_H */
