/* Host self-check for the route geometry predicates. Builds and runs on the
 * host (no NDK): the predicate decides whether a 5.15 entry is refused or
 * silently falls through to the non-compact pselect arm, so it is worth a
 * test that needs no device. See Makefile target route-geom-check. */
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "kernels/offsets.h"
#include "core/route_geom.h"

static const struct kernel_offsets *lookup(const char *release) {
  for (int i = 0; known_offsets[i].uname_r; i++) {
    if (strcmp(release, known_offsets[i].uname_r) == 0) {
      return &known_offsets[i];
    }
  }
  return NULL;
}

static void check(const char *release, int want) {
  const struct kernel_offsets *e = lookup(release);
  assert(e && "release missing from known_offsets");
  int got = mcast_geometry_ok_off(e);
  printf("%-8s mcast_geometry=%d wait=%d buf=%u lock=%u\n",
         release, got, e->mcast_waiter_off, e->mcast_buffer_size,
         e->mcast_lock_offset);
  assert(got == want);
}

int main(void) {
  /* 5.15's registered entry must carry a usable stamp */
  check("5.15.178-android13-8-00021-g6f2f96be86b9-ab13729987", 1);

  /* no mcast constants at all -> not selectable */
  const char *no_mcast = "6.1.138-android14-11-g44bda9e8f6e9-ab13792638";
  const struct kernel_offsets *e = lookup(no_mcast);
  assert(e && e->mcast_waiter_off == 0);
  assert(mcast_geometry_ok_off(e) == 0);

  /* the near-miss the old <= 0 guard let through: waiter_off > 0 but the
   * buffer stops short of lock_offset, so the stamp cannot cover the waiter */
  struct kernel_offsets near = *lookup("5.15.178-android13-8-00021-g6f2f96be86b9-ab13729987");
  near.mcast_buffer_size = 100; /* 96 + 56 + 8 = 160 > 100 */
  printf("%-8s buffer stops short -> geometry=%d (want 0)\n",
         "near", mcast_geometry_ok_off(&near));
  assert(mcast_geometry_ok_off(&near) == 0);

  /* exact-fit boundary must pass: waiter_off + lock_offset + 8 == buffer_size */
  struct kernel_offsets fit = near;
  fit.mcast_buffer_size = 96 + 56 + 8;
  assert(mcast_geometry_ok_off(&fit) == 1);

  /* NULL entry is not selectable */
  assert(mcast_geometry_ok_off(NULL) == 0);

  printf("route geometry checks passed\n");
  return 0;
}
