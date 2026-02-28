#ifndef _LINUX_SCATTERLIST_H
#define _LINUX_SCATTERLIST_H

#include <linux/types.h>
#include <linux/mm.h>

#define CONFIG_NEED_SG_DMA_LENGTH

__BEGIN_CDECLS

struct scatterlist
{
	unsigned long	page_link;
	unsigned int	offset;
	unsigned int	length;
	dma_addr_t	dma_address;
#ifdef CONFIG_NEED_SG_DMA_LENGTH
	unsigned int	dma_length;
#endif
#ifdef CONFIG_NEED_SG_DMA_FLAGS
	unsigned int    dma_flags;
#endif
};

/*
 * These macros should be used after a dma_map_sg call has been done
 * to get bus addresses of each of the SG entries and their lengths.
 * You should only work with the number of sg entries dma_map_sg
 * returns, or alternatively stop on the first sg_dma_len(sg) which
 * is 0.
 */
#define sg_dma_address(sg)	((sg)->dma_address)

#ifdef CONFIG_NEED_SG_DMA_LENGTH
#define sg_dma_len(sg)		((sg)->dma_length)
#else
#define sg_dma_len(sg)		((sg)->length)
#endif

#define SG_CHAIN	0x01UL
#define SG_END		0x02UL
#define SG_PAGE_LINK_MASK (SG_CHAIN | SG_END)

static inline struct page *sg_page(struct scatterlist *sg)
{
#ifdef CONFIG_DEBUG_SG
	BUG_ON(sg_is_chain(sg));
#endif
	return (struct page *)((sg)->page_link & ~SG_PAGE_LINK_MASK);
}

static inline unsigned long sg_flags(struct scatterlist *sg)
{
	return sg->page_link & SG_PAGE_LINK_MASK;
}

static inline bool sg_end(struct scatterlist *sg)
{
	return sg_flags(sg) == SG_END;
}

static inline void sg_mark_end(struct scatterlist *sg)
{
	sg->page_link |= SG_END;
	sg->page_link &= ~SG_CHAIN;
}

static inline bool sg_is_chain(struct scatterlist *sg)
{
	return sg_flags(sg) == SG_CHAIN;
}

static inline void sg_chain(struct scatterlist *sg, unsigned int previous_nents, struct scatterlist *next)
{
	sg[previous_nents - 1].page_link = ((unsigned long) next) | SG_CHAIN;
}

static inline struct scatterlist *sg_chain_ptr(struct scatterlist *sg)
{
	return (struct scatterlist *) (sg->page_link & ~SG_PAGE_LINK_MASK);
}

static inline void sg_assign_page(struct scatterlist *sg, struct page *page)
{
	unsigned long page_link = sg->page_link & (SG_CHAIN | SG_END);

	sg->page_link = page_link | (unsigned long) page;
}

static inline void sg_set_page(struct scatterlist *sg, struct page *page,
			       unsigned int len, unsigned int offset)
{
	sg_assign_page(sg, page);
	sg->length = len;
	sg->offset = offset;
}

static inline void sg_set_buf(struct scatterlist *sg, const void *buf,
			      unsigned int buflen)
{
	sg_assign_page(sg, phys_to_page(VIRT_TO_PHYS(buf)));
	sg->length = buflen;
	sg->offset = ((unsigned long) buf) & (PAGE_SIZE - 1);
}

struct sg_table {
	struct scatterlist *sgl;	/* the list */
	unsigned int nents;		/* number of mapped entries */
	unsigned int orig_nents;	/* original size of list */
};

/*
 * sg page iterator
 *
 * Iterates over sg entries page-by-page.  On each successful iteration, you
 * can call sg_page_iter_page(@piter) to get the current page.
 * @piter->sg will point to the sg holding this page and @piter->sg_pgoffset to
 * the page's page offset within the sg. The iteration will stop either when a
 * maximum number of sg entries was reached or a terminating sg
 * (sg_last(sg) == true) was reached.
 */
struct sg_page_iter {
	struct scatterlist	*sg;		/* sg holding the page */
	unsigned int		sg_pgoffset;	/* page offset within the sg */

	/* these are internal states, keep away */
	unsigned int		__nents;	/* remaining sg entries */
	int			__pg_advance;	/* nr pages to advance at the
						 * next step */
};

/* The exact same as sg_page_iter, but typesafe. */
struct sg_dma_page_iter {
	struct sg_page_iter base;
};

bool __sg_page_iter_next(struct sg_page_iter *piter);
void __sg_page_iter_start(struct sg_page_iter *piter,
			  struct scatterlist *sglist, unsigned int nents,
			  unsigned long pgoffset);

bool __sg_page_iter_dma_next(struct sg_dma_page_iter *piter);
void __sg_page_iter_dma_start(struct sg_dma_page_iter *piter,
			  struct scatterlist *sglist, unsigned int nents,
			  unsigned long pgoffset);


#define for_each_sg_page(sglist, piter, nents, pgoffset)		   \
	for (__sg_page_iter_start((piter), (sglist), (nents), (pgoffset)); \
	     __sg_page_iter_next(piter);)

#define for_each_sg_dma_page(sglist, piter, nents, pgoffset)		   \
	for (__sg_page_iter_dma_start((piter), (sglist), (nents), (pgoffset)); \
	     __sg_page_iter_dma_next(piter);)

/**
 * for_each_sgtable_page - iterate over all pages in the sg_table object
 * @sgt:	sg_table object to iterate over
 * @piter:	page iterator to hold current page
 * @pgoffset:	starting page offset (in pages)
 *
 * Iterates over the all memory pages in the buffer described by
 * a scatterlist stored in the given sg_table object.
 * See also for_each_sg_page(). In each loop it operates on PAGE_SIZE unit.
 */
#define for_each_sgtable_page(sgt, piter, pgoffset)	\
	for_each_sg_page((sgt)->sgl, piter, (sgt)->orig_nents, pgoffset)

#define for_each_sgtable_dma_page(sgt, piter, pgoffset)	\
	for_each_sg_dma_page((sgt)->sgl, piter, (sgt)->nents, pgoffset)

/**
 * sg_page_iter_page - get the current page held by the page iterator
 * @piter:	page iterator holding the page
 */
static inline struct page *sg_page_iter_page(struct sg_page_iter *piter)
{
	return sg_page(piter->sg) + piter->sg_pgoffset;
}

static inline dma_addr_t
sg_page_iter_dma_address(struct sg_dma_page_iter *dma_iter)
{
	return sg_dma_address(dma_iter->base.sg) + (dma_iter->base.sg_pgoffset << PAGE_SHIFT);
}

void sg_free_table(struct sg_table *table);

/**
 * sg_alloc_table_from_pages_segment - Allocate and initialize an sg table from
 *                                     an array of pages and given maximum
 *                                     segment.
 * @sgt:	 The sg table header to use
 * @pages:	 Pointer to an array of page pointers
 * @n_pages:	 Number of pages in the pages array
 * @offset:      Offset from start of the first page to the start of a buffer
 * @size:        Number of valid bytes in the buffer (after offset)
 * @max_segment: Maximum size of a scatterlist element in bytes
 * @gfp_mask:	 GFP allocation mask
 *
 *  Description:
 *    Allocate and initialize an sg table from a list of pages. Contiguous
 *    ranges of the pages are squashed into a single scatterlist node up to the
 *    maximum size specified in @max_segment. A user may provide an offset at a
 *    start and a size of valid data in a buffer specified by the page array.
 *
 *    The returned sg table is released by sg_free_table.
 *
 *  Returns:
 *   0 on success, negative error on failure
 */
int sg_alloc_table_from_pages_segment(struct sg_table *sgt, struct page **pages,
				unsigned int n_pages, unsigned int offset,
				unsigned long size, unsigned int max_segment,
				gfp_t gfp_mask);

int sg_alloc_table(struct sg_table *table, unsigned int nents, gfp_t gfp);

static inline struct scatterlist *sg_next(struct scatterlist *sg)
{
	if (unlikely(sg_end(sg)))
		return NULL;

	sg++;
	if (unlikely(sg_is_chain(sg)))
		return sg_chain_ptr(sg);
	return sg;
}

#define for_each_sg(sglist, sg, nr, __i)	\
	for (__i = 0, sg = (sglist); __i < (nr); __i++, sg = sg_next(sg))

#define for_each_sgtable_sg(sgt, sg, i)		\
	for_each_sg((sgt)->sgl, sg, (sgt)->orig_nents, i)

/*
 * Loop over each sg element in the given *DMA mapped* sg_table object.
 * Please use sg_dma_address(sg) and sg_dma_len(sg) to extract DMA addresses
 * of the each element.
 */
#define for_each_sgtable_dma_sg(sgt, sg, i)	\
	for_each_sg((sgt)->sgl, sg, (sgt)->nents, i)

__END_CDECLS
#endif
