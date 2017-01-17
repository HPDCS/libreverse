#ifndef _RALLOC_H
#define _RALLOC_H

#include <stdbool.h>
#include <unistd.h>

#include <reverse/reverse.h>

#define MPOOL_SIZE 4096

#define ACTIVE 0
#define FREED 1


typedef void *(*malloc_api)(size_t size);
typedef void (*free_api)(void *ptr);

typedef struct _memory_area_t {
	void *ptr;
	size_t size;
	unsigned int status;
	struct _memory_area_t *next;
} memory_area_t;


extern void ralloc_init(malloc_api _malloc, free_api _free);

extern void ralloc_fini(void);

extern void * rmalloc(reverse_t *rev, size_t size);

extern void rfree(reverse_t *rev, void * ptr);

extern void rcommit(reverse_t *rev);

#endif // _RALLOC_H