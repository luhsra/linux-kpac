#ifndef _LINUX_KPAC_NOP_H
#define _LINUX_KPAC_NOP_H

#include <linux/kpac_types.h>

static inline void kpac_reset_key(struct kpac_key *key) {}

static inline unsigned long kpac_pac(unsigned long plain, unsigned long tweak,
				     struct kpac_key *key)
{
	return plain;
}

static inline unsigned long kpac_aut(unsigned long cipher, unsigned long tweak,
				     struct kpac_key *key)
{
	return cipher;
}

#endif /* _LINUX_KPAC_NOP_H */
