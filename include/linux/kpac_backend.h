#ifndef _LINUX_KPAC_BACKEND_H
#define _LINUX_KPAC_BACKEND_H

#if defined(CONFIG_KPAC_BACKEND_NOP)
#include <linux/kpac/nop.h>
#elif defined(CONFIG_KPAC_BACKEND_XXHASH)
#include <linux/kpac/xxhash.h>
#else
#error "No pointer authentication backend selected"
#endif

#endif /* _LINUX_KPAC_BACKEND_H */
