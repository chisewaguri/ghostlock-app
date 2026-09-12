#include "iomem.h"

#include <stdlib.h>
#include <string.h>

/* Lowest start and highest end of the System RAM banks in a /proc/iomem dump.
 * A bank nested under another lies inside its parent, so children cannot widen
 * either bound and the indent needs no check. */
int iomem_map_span(FILE *f, uint64_t *map_span) {
  unsigned long long base = 0, top = 0;
  char *line = NULL;
  size_t cap = 0;

  while (getline(&line, &cap, f) > 0) {
    size_t len = strlen(line);
    unsigned long long a, b;
    int used = 0;

    while (len && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
      line[--len] = '\0';
    }
    /* %n pins the match to the whole line, sscanf still returns 2 when a
     * trailing literal mismatches */
    if (sscanf(line, " %llx-%llx : System RAM%n", &a, &b, &used) == 2 &&
        used == (int)len) {
      if (!base || a < base) base = a;
      if (b + 1 > top) top = b + 1;
    }
  }
  free(line);

  /* the map starts at the dram base the kernel rounded down to a gib, which
   * is what it puts in memstart_addr, and runs to the end of the last bank */
  base &= ~((1ULL << 30) - 1);
  if (!base || top <= base) return 0;
  *map_span = top - base;
  return 1;
}
