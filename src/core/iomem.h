#ifndef IOMEM_H
#define IOMEM_H

#include <stdint.h>
#include <stdio.h>

/* Length of the direct map, measured from the System RAM banks in a
 * /proc/iomem dump, with the dram base rounded down to a gib.  Consumes the
 * stream from its current position.  Returns 1 on a usable dump, 0 when it is
 * not one. */
int iomem_map_span(FILE *f, uint64_t *map_span);

#endif
