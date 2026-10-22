/* Host-side stand-in for libmicrokit: records notifications, no kernel. Test use only. */
#ifndef HOST_STUB_MICROKIT_H
#define HOST_STUB_MICROKIT_H
#include <stdint.h>
#include <stddef.h>
typedef unsigned int microkit_channel;
extern unsigned stub_notify_count[64];
static inline void microkit_notify(microkit_channel ch) { if (ch < 64) stub_notify_count[ch]++; }
static inline void microkit_dbg_puts(const char *s) { (void)s; }
#endif
