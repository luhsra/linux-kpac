// SPDX-License-Identifier: LGPL-2.1+
/*
 * ARMv8.3 QARMA implementation based on QEMU's target/arm/pauth_helper.c
 *
 * Copyright (c) 2019 Linaro, Ltd.
 * Copyright (c) 2022 Illia Ostapyshyn
 */

#ifndef _LINUX_KPAC_QARMA_H
#define _LINUX_KPAC_QARMA_H

#include <linux/kpac_types.h>
#include <linux/random.h>
#include <asm/types.h>

#define __KPAC_VA_MASK		((1ULL << VA_BITS) - 1)

#define MAKE_64BIT_MASK(shift, length) \
	(((~0ULL) >> (64 - (length))) << (shift))

static const char *const kpac_backend_name = "qarma";

static inline u64 extract64(u64 value, int start, int length)
{
	return (value >> start) & (~0ULL >> (64 - length));
}

static inline u32 extract32(u32 value, int start, int length)
{
	return (value >> start) & (~0U >> (32 - length));
}

static u64 pac_cell_shuffle(u64 i)
{
	u64 o = 0;

	o |= extract64(i, 52, 4);
	o |= extract64(i, 24, 4) << 4;
	o |= extract64(i, 44, 4) << 8;
	o |= extract64(i,  0, 4) << 12;

	o |= extract64(i, 28, 4) << 16;
	o |= extract64(i, 48, 4) << 20;
	o |= extract64(i,  4, 4) << 24;
	o |= extract64(i, 40, 4) << 28;

	o |= extract64(i, 32, 4) << 32;
	o |= extract64(i, 12, 4) << 36;
	o |= extract64(i, 56, 4) << 40;
	o |= extract64(i, 20, 4) << 44;

	o |= extract64(i,  8, 4) << 48;
	o |= extract64(i, 36, 4) << 52;
	o |= extract64(i, 16, 4) << 56;
	o |= extract64(i, 60, 4) << 60;

	return o;
}

static u64 pac_cell_inv_shuffle(u64 i)
{
	u64 o = 0;

	o |= extract64(i, 12, 4);
	o |= extract64(i, 24, 4) << 4;
	o |= extract64(i, 48, 4) << 8;
	o |= extract64(i, 36, 4) << 12;

	o |= extract64(i, 56, 4) << 16;
	o |= extract64(i, 44, 4) << 20;
	o |= extract64(i,  4, 4) << 24;
	o |= extract64(i, 16, 4) << 28;

	o |= i & MAKE_64BIT_MASK(32, 4);
	o |= extract64(i, 52, 4) << 36;
	o |= extract64(i, 28, 4) << 40;
	o |= extract64(i,  8, 4) << 44;

	o |= extract64(i, 20, 4) << 48;
	o |= extract64(i,  0, 4) << 52;
	o |= extract64(i, 40, 4) << 56;
	o |= i & MAKE_64BIT_MASK(60, 4);

	return o;
}

static u64 pac_sub(u64 i)
{
	static const u8 sub[16] = {
		0xb, 0x6, 0x8, 0xf, 0xc, 0x0, 0x9, 0xe,
		0x3, 0x7, 0x4, 0x5, 0xd, 0x2, 0x1, 0xa,
	};
	u64 o = 0;
	int b;

	for (b = 0; b < 64; b += 4) {
		o |= (u64)sub[(i >> b) & 0xf] << b;
	}
	return o;
}

static u64 pac_inv_sub(u64 i)
{
	static const u8 inv_sub[16] = {
		0x5, 0xe, 0xd, 0x8, 0xa, 0xb, 0x1, 0x9,
		0x2, 0x6, 0xf, 0x0, 0x4, 0xc, 0x7, 0x3,
	};
	u64 o = 0;
	int b;

	for (b = 0; b < 64; b += 4) {
		o |= (u64)inv_sub[(i >> b) & 0xf] << b;
	}
	return o;
}

static int rot_cell(int cell, int n)
{
	/* 4-bit rotate left by n.  */
	cell |= cell << 4;
	return extract32(cell, 4 - n, 4);
}

static u64 pac_mult(u64 i)
{
	u64 o = 0;
	int b;

	for (b = 0; b < 4 * 4; b += 4) {
		int i0, i4, i8, ic, t0, t1, t2, t3;

		i0 = extract64(i, b, 4);
		i4 = extract64(i, b + 4 * 4, 4);
		i8 = extract64(i, b + 8 * 4, 4);
		ic = extract64(i, b + 12 * 4, 4);

		t0 = rot_cell(i8, 1) ^ rot_cell(i4, 2) ^ rot_cell(i0, 1);
		t1 = rot_cell(ic, 1) ^ rot_cell(i4, 1) ^ rot_cell(i0, 2);
		t2 = rot_cell(ic, 2) ^ rot_cell(i8, 1) ^ rot_cell(i0, 1);
		t3 = rot_cell(ic, 1) ^ rot_cell(i8, 2) ^ rot_cell(i4, 1);

		o |= (u64)t3 << b;
		o |= (u64)t2 << (b + 4 * 4);
		o |= (u64)t1 << (b + 8 * 4);
		o |= (u64)t0 << (b + 12 * 4);
	}
	return o;
}

static u64 tweak_cell_rot(u64 cell)
{
	return (cell >> 1) | (((cell ^ (cell >> 1)) & 1) << 3);
}

static u64 tweak_shuffle(u64 i)
{
	u64 o = 0;

	o |= extract64(i, 16, 4) << 0;
	o |= extract64(i, 20, 4) << 4;
	o |= tweak_cell_rot(extract64(i, 24, 4)) << 8;
	o |= extract64(i, 28, 4) << 12;

	o |= tweak_cell_rot(extract64(i, 44, 4)) << 16;
	o |= extract64(i,  8, 4) << 20;
	o |= extract64(i, 12, 4) << 24;
	o |= tweak_cell_rot(extract64(i, 32, 4)) << 28;

	o |= extract64(i, 48, 4) << 32;
	o |= extract64(i, 52, 4) << 36;
	o |= extract64(i, 56, 4) << 40;
	o |= tweak_cell_rot(extract64(i, 60, 4)) << 44;

	o |= tweak_cell_rot(extract64(i,  0, 4)) << 48;
	o |= extract64(i,  4, 4) << 52;
	o |= tweak_cell_rot(extract64(i, 40, 4)) << 56;
	o |= tweak_cell_rot(extract64(i, 36, 4)) << 60;

	return o;
}

static u64 tweak_cell_inv_rot(u64 cell)
{
	return ((cell << 1) & 0xf) | ((cell & 1) ^ (cell >> 3));
}

static u64 tweak_inv_shuffle(u64 i)
{
	u64 o = 0;

	o |= tweak_cell_inv_rot(extract64(i, 48, 4));
	o |= extract64(i, 52, 4) << 4;
	o |= extract64(i, 20, 4) << 8;
	o |= extract64(i, 24, 4) << 12;

	o |= extract64(i,  0, 4) << 16;
	o |= extract64(i,  4, 4) << 20;
	o |= tweak_cell_inv_rot(extract64(i,  8, 4)) << 24;
	o |= extract64(i, 12, 4) << 28;

	o |= tweak_cell_inv_rot(extract64(i, 28, 4)) << 32;
	o |= tweak_cell_inv_rot(extract64(i, 60, 4)) << 36;
	o |= tweak_cell_inv_rot(extract64(i, 56, 4)) << 40;
	o |= tweak_cell_inv_rot(extract64(i, 16, 4)) << 44;

	o |= extract64(i, 32, 4) << 48;
	o |= extract64(i, 36, 4) << 52;
	o |= extract64(i, 40, 4) << 56;
	o |= tweak_cell_inv_rot(extract64(i, 44, 4)) << 60;

	return o;
}

static u64 __kpac_compute_pac(u64 data, u64 modifier, struct kpac_key *key)
{
	static const u64 RC[5] = {
		0x0000000000000000ull,
		0x13198A2E03707344ull,
		0xA4093822299F31D0ull,
		0x082EFA98EC4E6C89ull,
		0x452821E638D01377ull,
	};
	const u64 alpha = 0xC0AC29B7C97C50DDull;
	/*
	 * Note that in the ARM pseudocode, key0 contains bits <127:64>
	 * and key1 contains bits <63:0> of the 128-bit key.
	 */
	u64 key0 = key->qarma.hi, key1 = key->qarma.lo;
	u64 workingval, runningmod, roundkey, modk0;
	int i;

	modk0 = (key0 << 63) | ((key0 >> 1) ^ (key0 >> 63));
	runningmod = modifier;
	workingval = data ^ key0;

	for (i = 0; i <= 4; ++i) {
		roundkey = key1 ^ runningmod;
		workingval ^= roundkey;
		workingval ^= RC[i];
		if (i > 0) {
			workingval = pac_cell_shuffle(workingval);
			workingval = pac_mult(workingval);
		}
		workingval = pac_sub(workingval);
		runningmod = tweak_shuffle(runningmod);
	}
	roundkey = modk0 ^ runningmod;
	workingval ^= roundkey;
	workingval = pac_cell_shuffle(workingval);
	workingval = pac_mult(workingval);
	workingval = pac_sub(workingval);
	workingval = pac_cell_shuffle(workingval);
	workingval = pac_mult(workingval);
	workingval ^= key1;
	workingval = pac_cell_inv_shuffle(workingval);
	workingval = pac_inv_sub(workingval);
	workingval = pac_mult(workingval);
	workingval = pac_cell_inv_shuffle(workingval);
	workingval ^= key0;
	workingval ^= runningmod;
	for (i = 0; i <= 4; ++i) {
		workingval = pac_inv_sub(workingval);
		if (i < 4) {
			workingval = pac_mult(workingval);
			workingval = pac_cell_inv_shuffle(workingval);
		}
		runningmod = tweak_inv_shuffle(runningmod);
		roundkey = key1 ^ runningmod;
		workingval ^= RC[4 - i];
		workingval ^= roundkey;
		workingval ^= alpha;
	}
	workingval ^= modk0;

	return workingval;
}

static inline
void __kpac_reset_key(struct kpac_key *_key)
{
	struct kpac_key_u128 *key = &_key->qarma;
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

#endif /* _LINUX_KPAC_QARMA_H */
