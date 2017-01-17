#pragma once
#ifndef _REVERSE_H
#define _REVERSE_H

#include <sys/types.h>

// FIXME: l'inclusione genera un loop... (-.-)
//#include <mm/dymelor.h>

#define MASK 0x00000001		// Mask used to check, set and unset bits

// Macros to check, set and unset bits in the malloc_area masks
#define CHECK_USE_BIT(A,I) ( CHECK_BIT_AT(									\
			((unsigned int*)(((malloc_area*)A)->use_bitmap))[(int)((int)I / NUM_CHUNKS_PER_BLOCK)],	\
			((int)I % NUM_CHUNKS_PER_BLOCK)) )
#define SET_USE_BIT(A,I) ( SET_BIT_AT(										\
			((unsigned int*)(((malloc_area*)A)->use_bitmap))[(int)((int)I / NUM_CHUNKS_PER_BLOCK)],	\
			((int)I % NUM_CHUNKS_PER_BLOCK)) )
#define RESET_USE_BIT(A,I) ( RESET_BIT_AT(									\
			((unsigned int*)(((malloc_area*)A)->use_bitmap))[(int)((int)I / NUM_CHUNKS_PER_BLOCK)],	\
			((int)I % NUM_CHUNKS_PER_BLOCK)) )

#define CHECK_DIRTY_BIT(A,I) ( CHECK_BIT_AT(									\
			((unsigned int*)(((malloc_area*)A)->dirty_bitmap))[(int)((int)I / NUM_CHUNKS_PER_BLOCK)],\
			((int)I % NUM_CHUNKS_PER_BLOCK)) )
#define SET_DIRTY_BIT(A,I) ( SET_BIT_AT(									\
			((unsigned int*)(((malloc_area*)A)->dirty_bitmap))[(int)((int)I / NUM_CHUNKS_PER_BLOCK)],\
			((int)I % NUM_CHUNKS_PER_BLOCK)) )
#define RESET_DIRTY_BIT(A,I) ( RESET_BIT_AT(									\
			((unsigned int*)(((malloc_area*)A)->dirty_bitmap))[(int)((int)I / NUM_CHUNKS_PER_BLOCK)],\
			((int)I % NUM_CHUNKS_PER_BLOCK)) )

// Macros uset to check, set and unset special purpose bits
#define SET_LOG_MODE_BIT(A)     ( SET_BIT_AT(((malloc_area*)A)->chunk_size, 0) )
#define RESET_LOG_MODE_BIT(A) ( RESET_BIT_AT(((malloc_area*)A)->chunk_size, 0) )
#define CHECK_LOG_MODE_BIT(A) ( CHECK_BIT_AT(((malloc_area*)A)->chunk_size, 0) )

#define SET_AREA_LOCK_BIT(A)     ( SET_BIT_AT(((malloc_area*)A)->chunk_size, 1) )
#define RESET_AREA_LOCK_BIT(A) ( RESET_BIT_AT(((malloc_area*)A)->chunk_size, 1) )
#define CHECK_AREA_LOCK_BIT(A) ( CHECK_BIT_AT(((malloc_area*)A)->chunk_size, 1) )

#define SET_BIT_AT(B,K) ( B |= (MASK << K) )
#define RESET_BIT_AT(B,K) ( B &= ~(MASK << K) )
#define CHECK_BIT_AT(B,K) ( B & (MASK << K) )

#define IS_POWEROF2(x) (1UL << (1 + (63 - __builtin_clzl((x) - 1))))



#define REVWIN_SIZE 1024 * 32	//! Defalut size of the reverse window, i.e. the size of a single slab slice
#define REVWIN_MIN_SIZE 32		//! Minimum size of the reverse window, i.e. the size of a single slab slice

#define REVWIN_RZONE_SIZE 100		//! Size of the red zone in the reverse window that will be skipped to prevent cache misses
#define RANDOMIZE_REVWIN_CODE 0 	//! Activate the rendomization of the addresses used by revwin to prevent cache misses


#define STRATEGY_SINGLE 0
#define STRATEGY_CHUNK 1


// *** WARNING: BOTH MUST BE A POWER OF 2!!! *** //
#define CACHE_NUM_LINES 32
#define CACHE_LINE_SIZE 32

//
// address
//
// 63                k          x        0
// |-----------------|----------|--------|
// |       tag       |   line   |  addr  |
// |-----------------|----------|--------|
//
// x = lg2(CACHE_LINE_SIZE)
// k = lg2(CACHE_NUM_LINES) + x

#define CACHE_MASK_ADDR  ~(-CACHE_LINE_SIZE)
#define CACHE_MASK_LINE (~(-CACHE_NUM_LINES) << LOGPOWER2(CACHE_NUM_LINES))

// Works only with powers of 2
#define LOGPOWER2(x) (__builtin_ctzl(x))
#define INTDIV(d, q) ( (int)((int)(d) / (int)(q)) )


#define cache_lines(cache) (((reverse_cache_t *)cache)->lines)
#define line_bitmap(line) (((reverse_cache_line_t *)line)->bitmap)


#define get_cache_line(cache, address) (&( (((reverse_cache_t *)cache)->lines)[((address & CACHE_MASK_LINE) >> LOGPOWER2(CACHE_NUM_LINES)) % CACHE_NUM_LINES] ))

#define cache_set_bit(line, address) ( SET_BIT_AT( \
		((unsigned int *)(((reverse_cache_line_t *)line)->bitmap))[ (INTDIV((address & CACHE_MASK_ADDR), 32)) ], \
		(address % CACHE_LINE_SIZE) ) \
	)

#define cache_reset_bit(line, address) ( RESET_BIT_AT( \
		((unsigned int *)(((reverse_cache_line_t *)line)->bitmap))[ (INTDIV((address & CACHE_MASK_ADDR), 32)) ], \
		(address % CACHE_LINE_SIZE) ) \
	)

#define cache_check_bit(line, address) ( CHECK_BIT_AT( \
		((unsigned int *)(((reverse_cache_line_t *)line)->bitmap))[ (INTDIV((address & CACHE_MASK_ADDR), 32)) ], \
		(address % CACHE_LINE_SIZE) ) \
	)

#define get_address_tag(address) (address >> (LOGPOWER2(CACHE_NUM_LINES) + LOGPOWER2(CACHE_LINE_SIZE)))


typedef struct _reverse_cache_line_t {
	unsigned long long tag;
	unsigned int total_hits;
	unsigned int distinct_hits;
	unsigned int bitmap[CACHE_LINE_SIZE];
} reverse_cache_line_t;


typedef struct _reverse_cache_t {
	double usefulness;
	reverse_cache_line_t lines[CACHE_NUM_LINES];
} reverse_cache_t;


// The cache must primarily checks whether an address exists, therefore keep track of
// the number of accesses that have been performed for each chunk. Input address is used
// to retrieve a k-bits prefix to uniquely identify a cache line which contains the
// information relative to the current registered cluster. Each line holds a set of metadata
// fields that keep track of the hit cluster ratio and the number of different addresses
// referenced.
// First of all the cache provides the presence bit of the requested address, then it updates
// its metadata, either online or through a different thread.
// Strategy switch can be based on the ratio = width / tagHit.
// In case a new distinct address will be referenced (i.e. its presence bit has been set), then
// the cache's usefulness will be updatet as well; on the contrary, if a cache miss occurs, no
// action will be taken to modify the cache's metadata.
// A cache miss simply occurs whenever the requested address belongs to a cluster whose tag differ
// from the one stored in the selected cache line.


/**
 * Computes the available size to store code or data.
 */
#define revwin_avail_size(w) ((unsigned long)(w)->code - (unsigned long)(w)->data)

/**
 * Computes the actual size of executable code section.
 */
#define revwin_code_size(w) ((unsigned long)(w)->code_start - (unsigned long)(w)->code)

/**
 * Computes the actual size of executable data section.
 */
#define revwin_data_size(w) ((unsigned long)(w)->data - (unsigned long)(w)->data_start)


/**
 * Descriptor of a single reverse window
 */
 typedef struct _revwin_t {
 	// Header
 	void *code_start;			//! Initial address where executable starts
 	void *data_start;			//! Initial address where dumped data starts
 	void *data;					//! Placeholder where the tip of the data dump is
	void *code;					//! Placeholder for the tip of executable reverse code, i.e. the point where the executable code is
	struct _revwin_t * parent;	//! Link to the parent revwin, in case of overflow
	
	// Raw bytes payload
	// (executable and data)
	char raw[];					//! Where the payload section of the reverse window starts
} revwin_t;


/**
 * Descriptor for the reverse code handler
 */
typedef struct _reverse_t {
	revwin_t *window;		//! Current top revwin
	void *mpool;
} reverse_t;


//! Use XMM instruction to generate inverse code
extern bool use_xmm;

/**
 * Enable the check for the dominance property to choose whether to
 * generate the inverse of the code or not.
 * This means that the software cache will be used to track which
 * memory area has been saved yet.
 */
extern bool enable_dominance_check;


// ========================================= //
// ================== API ================== //

/**
 * Initialize a thread local reverse manager to build and populate reverse windows
 * for the simulation events. This manager leans on a SLAB allocator to fast handle
 * creation and destruction of reverse windows.
 *
 * @author Davide Cingolani
 *
 * @param revwin_sise The size the SLAB will allocate for each reverse window
 */
extern void reverse_init(size_t revwin_size);

/** 
 * Finalize the reverse manager. It must be called at the end of the overall execution
 * in order to clean up the internal allocator and free the resources.
 *
 * @author Davide Cingolani
 */
extern void reverse_fini(void);


/**
 * Initializes locally a new reverse window.
 *
 * @author Davide Cingolani
 */
//extern reverse_t *revwin_create(void);


/**
 * Set the revwin to use for the reverse process.
 *
 * @author Davide Cingolani
 */
extern reverse_t * revwin_create(void);


extern void revwin_destroy(reverse_t *rev);

/**
 * Set the revwin to use for the reverse process.
 *
 * @author Davide Cingolani
 */
extern void revwin_use(reverse_t *);


/**
 * Free the reverse window passed as argument.
 *
 * @author Davide Cingolani 
 *
 * @param window A pointer to a reverse window
 */
//extern void revwin_free(reverse_t *win);


/**
 * Reset local reverse window
 *
 * @author Davide Cingolani 
 *
 * @param lid The ID of the LP issuing the execution
 * @param win Pointer to the reverse window descriptor
 */
extern void revwin_reset(reverse_t *win);


/**
 * Prompt the execution of the specified reverse window.
 *
 * @author Davide Cingolani 
 *
 * @param lid The ID of the LP issuing the execution
 * @param win Pointer to the reverse window descriptor
 */
extern void execute_undo_event(reverse_t *win);


/**
 * Prints some statistics of the software 
 *
 * @author Davide Cingolani 
 */
extern void print_cache_stats(void);


/**
 * Computes the actual size of the passed reverse window.
 *
 * @author Davide Cingolani
 *
 * @param win Pointer to the reverse window descriptor
 *
 * @returns A size_t representing the size of the passed reverse window
 */
//extern size_t revwin_size(revwin_t *win);


/**
 * Clean up the software cache used to keep track of the reversed addresses.
 * Upon this cache is built the model to choose the reversing strategy to
 * apply.
 *
 * @author Davide Cingolani
 *
 */

extern void revwin_flush_cache(void);

#endif /* _REVERSE_H */
