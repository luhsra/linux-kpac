#ifndef _LINUX_KPAC_SIPHASH_H
#define _LINUX_KPAC_SIPHASH_H

#include <linux/kpac_types.h>
#include <linux/siphash.h>
#include <linux/random.h>
#include <asm/types.h>

#define __KPAC_VA_MASK		((1ULL << VA_BITS) - 1)

static const char *const kpac_backend_name = "siphash";

static inline
unsigned long __kpac_compute_pac(unsigned long plain, unsigned long tweak,
				 struct kpac_key *_key)
{
	return siphash_2u64(plain, tweak, &_key->siphash);
}

static inline
void __kpac_reset_key(struct kpac_key *_key)
{
	get_random_bytes(&_key->siphash, sizeof(_key->siphash));
}

static inline
unsigned long __kpac_pac(unsigned long plain, unsigned long tweak,
			 struct kpac_key *key)
{
	unsigned long pac;
	plain &= __KPAC_VA_MASK;
	pac = __kpac_compute_pac(plain, tweak, key) & ~__KPAC_VA_MASK;

	return pac | plain;
}

static inline
unsigned long __kpac_aut(unsigned long cipher, unsigned long tweak,
			 struct kpac_key *key)
{
	unsigned long pac, plain;
	plain = cipher & __KPAC_VA_MASK;
	pac = __kpac_compute_pac(plain, tweak, key) & ~__KPAC_VA_MASK;

	if ((pac | plain) != cipher)
		plain |= 1UL << (BITS_PER_LONG-1);
	return plain;
}

#endif /* _LINUX_KPAC_SIPHASH_H */
