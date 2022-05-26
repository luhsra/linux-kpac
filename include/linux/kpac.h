#ifndef _LINUX_KPAC_H
#define _LINUX_KPAC_H

#include <linux/mm.h>

void kpac_migrate(struct task_struct *p, int cpu);
int kpac_exec(void);

#endif	/* _LINUX_KPAC_H */
