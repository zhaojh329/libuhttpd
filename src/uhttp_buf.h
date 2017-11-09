#ifndef _UHTTP_BUF_H
#define _UHTTP_BUF_H

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

#define UH_BUF_SIZE_MULTIPLIER 1.5

struct uh_buf {
	char *base;		/* Buffer pointer */
	size_t len;		/* Data length */
	size_t size;	/* Buffer size */
};

#define uh_buf_available(b) ((b)->size - (b)->len)

/* Return 0 for successful or -1 if out of memory */
int uh_buf_init(struct uh_buf *buf, size_t initial_size);
int uh_buf_grow(struct uh_buf *buf, size_t size);

void uh_buf_free(struct uh_buf *buf);

/* Append data to the buf. Return the number of bytes appended. */
size_t uh_buf_append(struct uh_buf *buf, const void *data, size_t len);

/* Remove n bytes of data from the beginning of the buffer. */
void uh_buf_remove(struct uh_buf *buf, size_t n);

#endif
