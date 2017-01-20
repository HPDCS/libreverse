#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>

#include "hash.h"

unsigned int lock;

unsigned long long hash(const void *data, size_t size) {
	unsigned int i;
	unsigned long long hash;

	if (data == NULL) {
		return 0;
	}

	hash = 0;

	for (i = 0; i < size; i++) {
		hash = *(unsigned char *)(data + i) + (hash << 6) + (hash << 16) - hash;
	}

	return hash;
}
