#ifndef _LINUX_KPAC_BACKEND_H
#define _LINUX_KPAC_BACKEND_H

/*
 * See linux/kpac/nop.h for an example of a minimal hashing backend and what
 * kind of functions/variables they should provide.
 */

#if defined(CONFIG_KPAC_BACKEND_NOP)
#include <linux/kpac/nop.h>
#elif defined(CONFIG_KPAC_BACKEND_XXHASH)
#include <linux/kpac/xxhash.h>
#elif defined(CONFIG_KPAC_BACKEND_QARMA)
#include <linux/kpac/qarma.h>
#elif defined(CONFIG_KPAC_BACKEND_SIPHASH)
#include <linux/kpac/siphash.h>
#else
#error "No pointer authentication backend selected"
#endif

#endif /* _LINUX_KPAC_BACKEND_H */
