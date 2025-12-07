#ifndef _LINUX_PAGEVEC_H
#define _LINUX_PAGEVEC_H

#include <onyx/folio_batch.h>
#include <linux/mm.h>

#define __folio_batch_release(batch) folio_end_batch(batch)
#define folio_batch_release(batch) folio_end_batch(batch)

#endif
