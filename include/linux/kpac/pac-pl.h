#ifndef _LINUX_KPAC_PAC_PL_H
#define _LINUX_KPAC_PAC_PL_H

#include <linux/kpac_types.h>
#include <asm/io.h>

#define PAC_PL_BASE		0xA0001000UL
#define PAC_PL_PLAIN		0
#define PAC_PL_TWEAK		8
#define PAC_PL_CIPHER		16

#define STR1(x)  #x
#define STR(x)   STR1(x)

extern void *pac_pl_base;

static const char *const kpac_backend_name = "pac-pl";

static inline void __kpac_reset_key(struct kpac_key *key) {}

static inline unsigned long __kpac_pac(unsigned long plain, unsigned long tweak,
				       struct kpac_key *key)
{
	asm volatile ("1: stp %0, %1, [%2, #" STR(PAC_PL_PLAIN) "]\n"
		      "ldr %0, [%2, #" STR(PAC_PL_CIPHER) "]\n"
		      : "+&r" (plain)
		      : "r" (tweak), "r" (pac_pl_base));
	return plain;
}

static inline unsigned long __kpac_aut(unsigned long cipher, unsigned long tweak,
				       struct kpac_key *key)
{
	asm volatile ("1: stp %1, %0, [%2, #" STR(PAC_PL_TWEAK) "]\n"
		      "ldr %0, [%2, #" STR(PAC_PL_CIPHER) "]\n"
		      : "+&r" (cipher)
		      : "r" (tweak), "r" (pac_pl_base));
	return cipher;
}

#endif /* _LINUX_KPAC_PAC_PL_H */
