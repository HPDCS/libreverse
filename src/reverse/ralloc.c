#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <assert.h>

#include <reverse/reverse.h>
#include <reverse/ralloc.h>

#define unlikely(x)	__builtin_expect(x, 0)
#define likely(x)	__builtin_expect(x, 1)

static memory_area_t *mempool_head;

static malloc_api malloc_callback = (malloc_api) 0xDEADC0DE;
static free_api free_callback = (free_api) 0xDEADC0DE;


extern void revwin_add_code(revwin_t *win, unsigned char *bytes, size_t size);


void ralloc_init(malloc_api _malloc, free_api _free) {
	// mempool_head = malloc(MPOOL_SIZE * sizeof(memory_area_t));
	// if(mempool_head == NULL) {
	// 	// errore
	// }

	mempool_head = malloc(sizeof(memory_area_t));
	bzero(mempool_head, sizeof(memory_area_t));

	malloc_callback = _malloc;
	free_callback = _free;
}


void ralloc_fini(void) {
	// free(mempool_head);
}

void * rmalloc(reverse_t *rev, size_t size) {
	memory_area_t *area;
	void *ptr;
	void *foo;

	uint8_t code[22] = {
		0x48, 0xb8, 0xda, 0xd0, 0xda,				// ...
		0xd0, 0x00, 0x00, 0x00, 0x00,				// movabs $0x0, %rax
		0x48, 0x89, 0xc7,							// movq %rax, %rdi
		//0xbe, 0xd3, 0xb0, 0x00, 0x00,				// movl $0, %esi
		0x48, 0xc7, 0xc0, 0x00, 0x00, 0x00, 0x00,	// movl $0, %eax
		0xff, 0xd0									// call *%rax
	};


	//area = (memory_area_t *)rev->mpool;

	printf("Call to rmalloc for size %ld\n", size);

	// 1. First we malloc a new memory of the requested size
	ptr = malloc_callback(size);
	if(ptr == NULL) {
		return ptr;
	}

	// 2. We need to track this area inta a reversible instruction.
	// In particular, we also need to add a call to free in the
	// current revwin with this address

	foo = free_callback;

	memcpy(code+2, &ptr, 8);
	memcpy(code+16, &foo, 4);

	revwin_add_code(rev->window, code, sizeof(code));

	return ptr;
}

static void ufree(memory_area_t **head, void *ptr) {
	memory_area_t *area;

	area = *head;

	//assert(area->ptr == ptr);
	printf("pool at %p, %p\n", head, *head);
	*head = area->next;
	
	free(area);
}

void rfree(reverse_t *rev, void *ptr) {
	memory_area_t *area, *head;
	void *foo;

	uint8_t code[22] = {
		0x48, 0xb8, 0xda, 0xd0, 0xda,				// ...
		0xd0, 0x00, 0x00, 0x00, 0x00,				// movabs $0x0, %rax
		0x48, 0x89, 0xc7,							// movq %rax, %rdi
		//0x48, 0xb8, 0xda, 0xd0, 0xda,				// ...
		//0xd0, 0x00, 0x00, 0x00, 0x00,				// movabs $0x0, %rax
		//0x48, 0x89, 0xc6,							// movq %rax, %rsi
		//0xbe, 0xd3, 0xb0, 0x00, 0x00,				// movl $0, %esi
		0x48, 0xc7, 0xc0, 0x00, 0x00, 0x00, 0x00,	// movl $0, %eax
		0xff, 0xd0									// call *%rax
	};

	printf("Call rfree for pointer %p\n", ptr);
 
	// The rfree must add the memory pointer to the
	// marked list, so that it can be flushed safely
	// at the commit phase.
	area = malloc(sizeof(memory_area_t));
	if(area == NULL) {
		printf("Error on rfree: insufficient memory");
		abort();
	}

	// Set the metadata
	area->ptr = ptr;
	area->status = FREED;

	head = (memory_area_t *)rev->mpool;

	// Head insert
	if(unlikely(head == NULL)){
		rev->mpool = head = area;
	}
	else {
		area->next = head->next;
		head->next = area;
	}

	foo = ufree;

	memory_area_t **pool;
	pool = &rev->mpool;

	memcpy(code+2, &pool, 8);
	memcpy(code+16, &foo, 4);

	revwin_add_code(rev->window, code, sizeof(code));
}

void rcommit(reverse_t *rev) {
	memory_area_t *area;

	assert(rev != NULL);
	area = (memory_area_t *)rev->mpool;

	// Commit marked memory areas to be free
	// by invoking the relative free function
	while(area != NULL) {
		printf("Real free of pointer %p\n", area->ptr);

		free_callback(area->ptr);
		free(area);
		area = area->next;
	}
}
