#ifndef _GOTPLT_H
#define _GOTPLT_H

#include <unistd.h>

#define get_code_ptr(code, lbl_off) (unsigned char *)(code) + (int)(lbl_off)

#define MODE_PLATFORM	0
#define MODE_REVERSIBLE	1

/**
 * This is the operational mode flag
 */
extern __thread int _dso_mode;

typedef struct _symbol_info_t {
	char name[128];
	char *address;
	size_t size;
	struct _symbol_info_t *next;
} symbol_info_t ;


extern void switch_operational_mode(int flags);

#endif // _GOTPLT_H