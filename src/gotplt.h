#ifndef _GOTPLT_H
#define _GOTPLT_H

#include <unistd.h>


typedef struct _symbol_info_t {
	char name[128];
	char *address;
	size_t size;
	struct _symbol_info_t *next;
} symbol_info_t ;

#endif // _GOTPLT_H