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

#endif
