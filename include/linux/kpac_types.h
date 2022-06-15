#ifndef _LINUX_KPAC_TYPES_H
#define _LINUX_KPAC_TYPES_H

#include <asm/types.h>

struct kpac_key_u128 {
	u64 hi, lo;
};

struct kpac_key {
	/*
	 * Since sched.h needs the kpac context definition, reserve space for
	 * all key format to avoid recompilation when switching backends.
	 */
	union {
		struct kpac_key_u128 xxhash;
	};
};

/* Registers used for communication with applications */
struct kpac_area {
	unsigned long status;	/* Request or 0 when idle */
	unsigned long plain;	/* Plain pointer */
	unsigned long tweak;	/* Context-based salt */
	unsigned long cipher;	/* Signed pointer */
};

/* Context of the device saved in the task state */
struct kpac_context {
	struct kpac_area area;
	struct kpac_key key;
};

#endif /* _LINUX_KPAC_TYPES_H */
