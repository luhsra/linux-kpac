#ifndef _LINUX_KPAC_H
#define _LINUX_KPAC_H

struct task_struct;		/* in linux/sched.h */

#define KPAC_NR_REGS	4

/* Context of the device saved in the TCB */
struct kpac_context {
	unsigned long regs[4];
};

void kpac_switch(struct task_struct *p);
void kpac_migrate(struct task_struct *p, int cpu);
int kpac_exec(void);

#endif	/* _LINUX_KPAC_H */
