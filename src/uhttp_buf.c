#include <assert.h>
#include <string.h>
#include "uhttp_buf.h"

int uh_buf_init(struct uh_buf *buf, size_t initial_size)
{
	buf->len = buf->size = 0;

	if (buf->base) {
		free(buf->base);
		buf->base = NULL;
	}

	if (initial_size > 0) {
		buf->base = malloc(initial_size);
		if (!buf->base)
			return -1;
		buf->size = initial_size;
	}

	return 0;
}

int uh_buf_grow(struct uh_buf *buf, size_t size)
{
	void *base = realloc(buf->base, buf->size + size);
	if (!base)
		return -1;
	
	buf->base = base;
	buf->size += size;
	return 0;
}

void uh_buf_free(struct uh_buf *buf)
{
	if (buf->base) {
		free(buf->base);
		uh_buf_init(buf, 0);
	}
}

size_t uh_buf_append(struct uh_buf *buf, const void *data, size_t len)
{
	assert(buf);

	if (!data)
		return 0;

	if (buf->len + len > buf->size) {
		if (uh_buf_grow(buf, len * UH_BUF_SIZE_MULTIPLIER) == -1)
			len = buf->size - buf->len;
	}

	memcpy(buf->base + buf->len, data, len);
	buf->len += len;

	return len;
}

void uh_buf_remove(struct uh_buf *buf, size_t n)
{
	if (n > 0 && n <= buf->len) {
		memmove(buf->base, buf->base + n, buf->len - n);
		buf->len -= n;
	}
}