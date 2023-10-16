#ifndef _LINUX_KPAC_TYPES_H
#define _LINUX_KPAC_TYPES_H
#ifdef CONFIG_KPAC

#include <asm/types.h>
#include <linux/siphash.h>

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
		struct kpac_key_u128 qarma;
		siphash_key_t siphash;
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

#endif /* CONFIG_KPAC */
#endif /* _LINUX_KPAC_TYPES_H */
