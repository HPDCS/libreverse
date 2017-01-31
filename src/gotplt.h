#ifndef _GOTPLT_H
#define _GOTPLT_H

#include <unistd.h>

#define get_code_ptr(code, lbl_off) (unsigned char *)(code) + (int)(lbl_off)

#define MODE_PLATFORM	0
#define MODE_REVERSIBLE	1

/**
 * Hold the operational mode flag
 */
extern __thread int _dso_mode;

/**
 * Hold the information relative to one dynamic symbol
 * the software depends on.
 */
typedef struct _symbol_info_t {
	char name[128];
	char *address;
	size_t size;
	struct _symbol_info_t *next;
} symbol_info_t ;

typedef struct instrument_info_t {
	int offset;			//! The offset of the current instruction within the start of the code
	int index;			//! The index of the current insturction within the instrument_table
} instrument_info_t;

typedef instrument_info_t *insturment_table_t;


extern void switch_operational_mode(int flags);

#endif // _GOTPLT_H