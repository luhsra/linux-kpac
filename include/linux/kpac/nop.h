#ifndef _LINUX_KPAC_NOP_H
#define _LINUX_KPAC_NOP_H

#include <linux/kpac_types.h>

static const char *const kpac_backend_name = "nop";

static inline void __kpac_reset_key(struct kpac_key *key) {}

static inline unsigned long __kpac_pac(unsigned long plain, unsigned long tweak,
				       struct kpac_key *key)
{
	return plain;
}

static inline unsigned long __kpac_aut(unsigned long cipher, unsigned long tweak,
				       struct kpac_key *key)
{
	return cipher;
}

#endif /* _LINUX_KPAC_NOP_H */
