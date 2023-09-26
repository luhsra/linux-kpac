#ifndef _LINUX_KPAC_XXHASH_H
#define _LINUX_KPAC_XXHASH_H

#include <linux/kpac_types.h>
#include <linux/xxhash.h>
#include <linux/random.h>
#include <asm/types.h>

#define __KPAC_VA_MASK		((1ULL << VA_BITS) - 1)
#define __KPAC_XXHASH_SEED 	1

static const char *const kpac_backend_name = "xxhash";

static inline
unsigned long __kpac_compute_pac(unsigned long plain, unsigned long tweak,
				 struct kpac_key *_key)
{
	struct kpac_key_u128 *key = &_key->xxhash;
	u64 input[4] = { plain, tweak, key->lo, key->hi };

	return xxh64(input, sizeof(input), __KPAC_XXHASH_SEED);
}

static inline
void __kpac_reset_key(struct kpac_key *_key)
{
	struct kpac_key_u128 *key = &_key->xxhash;
	get_random_bytes(key, sizeof(*key));
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

#endif /* _LINUX_KPAC_XXHASH_H */
