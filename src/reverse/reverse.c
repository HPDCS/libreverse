#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
#include <errno.h>
#include <stdbool.h>
#include <assert.h>

#include <reverse/reverse.h>
//#include <dymelor.h>
#include <mm/slab.h>


//
//             revwin
//       ====================
//       ||     header     ||
//       ||----------------||
// data->||      data      ||
//       ||                ||
//       ||----------------||
//       ||                ||
//       ||                ||
//       ||                ||
//       ||      code      ||
// code->||                ||
//       ====================
// 


//! Use XMM instruction to generate inverse code
bool use_xmm = false;

/**
 * Enable the check for the dominance property to choose whether to
 * generate the inverse of the code or not.
 * This means that the software cache will be used to track which
 * memory area has been saved yet.
 */
bool enable_dominance_check = false;

//! Actual strategy in use to generate inverse code: single instruction or chunck-based
static int strategy_id = STRATEGY_SINGLE;

//! Actual size of the revwin to use
static unsigned int revwin_size = REVWIN_SIZE;

static int dominated_count = 0;

//! Internal software cache to keep track of the reversed instructions
static __thread reverse_cache_t cache;

//! Keeps track of the current reversing strategy
//__thread strategy_t strategy;

//! Handling of the reverse windows
static struct slab_chain *slab_chain;

// FIXME: necessario trovare un metodo alternativo per mantenere la current window
//! Pointer (per-thread) to the currently active reverse window
static __thread reverse_t *reverse = NULL;



void revwin_add_code(revwin_t *win, unsigned char *bytes, size_t size);

/**
 * Create a new empty reverse window.
 *
 * @author Davide Cingolani
 */
static revwin_t * revwin_alloc(void) {
	revwin_t *win;

	// One POP %rax and one RET
	//unsigned char code_closing[2] = {0x58, 0xc3};

	assert(slab_chain != NULL);

	// Query the slab allocator to retrieve a new reverse window
	// executable area. The address represents the base address of
	// the revwin descriptor which contains the reverse code itself.
	win = slab_alloc(slab_chain);
	if(win == NULL) {
		printf("Unable to allocate a new reverse window: SLAB failure\n");
		abort();
	}

	// Clear the revwin
	bzero(win, revwin_size + sizeof(revwin_t));

	// Initialize reverse window's code field in order to point to very
	// last byte of the raw section of this reverse window
	win->code_start = (void *)((char *)win->raw + revwin_size - 1);
	win->data_start = win->raw;

	// Allocate a new slot in the reverse mapping, accorndigly to
	// the number of yet allocated windows
#if RANDOMIZE_REVWIN_CODE
	win->code_start = (void *)((char *)win->code_start - (rand() % REVWIN_RZONE_SIZE));
#endif

	win->code = win->code_start;
	win->data = win->data_start;

	// No other particular initialization for data pointer is required

	// Initialize the executable code area with the closing
	// instructions at the end of the actual window.
	// In this way we are sure the exection will correctly returns
	// once the whole revwin has been reverted.
	//revwin_add_code(win, code_closing, sizeof(code_closing));

	// Update the code_start in order not to have to rewrite
	// the closing instructions at each reset
	//win->code_start = win->code;

	return win;
}


static void revwin_free(revwin_t *win) {

	// Sanity check
	if (win == NULL) {
		return;
	}

	bzero(win, revwin_size + sizeof(revwin_t));

	// Free the slab area
	slab_free(slab_chain, win);
}


//
//         <0x1000>  revwin_1        <0x1200> revwin_2
//        ====================     ==================== <- current window
//        ||     header     ||     ||     header     ||
//        ||----------------||     ||----------------||
// data ->||      data      ||     ||      data      ||
//        ||                ||     ||                ||
// code ->||----------------||     ||----------------||
//    --->|| movl           ||     || push           ||
//    |   || movl           ||     || ...            ||
//    |   || movl           ||     || movl           ||
//    |   || pop            ||     || movl           ||
//    |   || ret            ||     || jmp <revwin>   ||------
//    |   ====================     ====================     |
//    |                                                     |
//    -------------------------------------------------------

/**
 * Create a new overflow reverse window to link with. Overflow window is
 * linked to the previous by the 'next' field in the header structure and
 * to this window will be added a JMP instruction to the first byte of code
 * relative to the parent reverse widnow. In this way we guarantee that
 * the reverse execution will be seamless.
 *
 * @author Davide Cingolani
 *
 * @param win Pointer to the reverse window that overflows
 */
static void revwin_overflow(reverse_t *rev) {
    unsigned char jmp[5] = {0xe9, 0x00, 0x00, 0x00, 0x00};
    int offset;
    revwin_t *win;

    // Allocates a new revwin to continue and place a jmp instruction to the offset
    // in the previous window where to continue the execution, i.e. where the code
    // pointer is stopped.
    // NOTE: We must consider the header and the data sections of the window 
    revwin_t *ofwin = revwin_alloc();
    win = rev->window;

    // Offset is negative, since the parent window is at a less address
    // and the code is placed in a stack flavour.
    //   old  := where the code pointer stops in the parent window
    //   curr := where the code pointer starts in the current window
    // offset = (old - curr)
    offset = (unsigned char *)win->code - (unsigned char *)ofwin->code;
    memcpy(jmp+1, &offset, 4);
    
    // Add the JMP instruction to the parent window
    revwin_add_code(ofwin, jmp, sizeof(jmp));
    
    // Add the pointer to the parent window and update the current pointer
    ofwin->parent = rev->window;
    rev->window = ofwin;

    printf("Overflow revwin at <%p> has been created and linked to <%p>\n", ofwin, win);
}


/**
 * Check whether there is enough available space in the reverse window
 * to add new data or instructions.
 *
 * @author Davide Cingolani
 */
static inline bool revwin_check_space(revwin_t *win, size_t size) {
	// printf("Code size: %lu bytes; Data size: %lu bytes\n",
	// 	revwin_code_size(win), revwin_data_size(win));

	// printf("Still available: %lu bytes (of %u); request of %u bytes\n",
	//	revwin_avail_size(win), (unsigned int)revwin_size, (unsigned int)size);

	/*if ((size_t)((long long)win->code - (long long)win->data) < (size)) {
        printf("Request for %d bytes failed!\n", (int)size);
		revwin_overflow(win);
	}*/

	assert(revwin_size > size);

	return (revwin_avail_size(win) > size);
}


/**
 * Add exeutable code provided to the executable section of the reverse window.
 *
 * @author Davide Cingolani
 *
 * @param win Reverse window pointer
 * @param bytes Pointer to the buffer to write
 * @param size Number of bytes to write
 */
void revwin_add_code(revwin_t *win, unsigned char *bytes, size_t size) {

	assert(win != NULL);
	
	// Since the structure is used as a stack, it is needed to create room for the instruction
	win->code = (void *)((char *)win->code - size);

	// copy the instructions to the heap
	memcpy(win->code, bytes, size);
}


/**
 * Add data provided to the data section of the reverse window
 *
 * @author Davide Cingolani
 *
 * @param win Reverse window pointer
 * @param address Pointer to the buffer which contains the data to add
 * @param size The size in bytes of the provided buffer
 */
static inline void revwin_add_data(revwin_t *win, void *address, size_t size) {

	assert(win != NULL);

	memcpy(win->data, address, size);

	win->data = (void *)((char *)win->data + size);
}


/**
 * Generates the reversing instruction for a whole chunk.
 *
 * @author Davide Cingolani
 *
 * @param address The starting address from which to copy
 * @param size The number of bytes to reverse
 */
static void reverse_chunk(reverse_t *rev, unsigned long long address, size_t size) {
	unsigned char code[36] = {
		0x48, 0xc7, 0xc1, 0x00, 0x00, 0x00, 0x00,							// mov 0x0,%rcx
		0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,			// movabs 0x0,%rax
		0x48, 0x89, 0xc6,													// mov %rax,%rsi
		0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,			// movabs 0x0,%rax
		0x48, 0x89, 0xc7,													// mov %rax,%rdi
		0xf3, 0x48, 0xa5													// rep movsq
	};
	// TODO: movsq non è sicura, i chunk potrebbero non essere multipli di 8 byte
	// TODO: usare i registri xmm per spostare 128 bit alla volta (attenzione all'allineamento, però!!)

	unsigned char *mov_rcx = code;
	unsigned char *mov_rsi = code + 7;
	unsigned char *mov_rdi = code + 20;

	revwin_t *win;
	win = rev->window;

	// Check whether there is enough available space to store data
	// TODO
	if(!revwin_check_space(win, size)) {
		revwin_overflow(rev);
		win = rev->window;
	}

	// Dump the chunk to the reverse window data section
	memcpy(win->data, (void *)address, size);

	#ifdef REVERSE_SSE_SUPPORT
	// TODO: support sse instructions
	#else

	// Copy the chunk size in RCx
	memcpy(mov_rcx+3, &size, 4);
	
	// Copy the first address
	memcpy(mov_rsi+2, &win->data, 8);

	// Compute and copy the second part of the address
	memcpy(mov_rdi+2, &address, 8);
	#endif

	win->data = (void *)((char *)win->data + size);

	//printf("Chunk addresses reverse code generated\n");

	// Now 'code' contains the right code to add in the reverse window
	if(!revwin_check_space(win, sizeof(code))) {
		revwin_overflow(rev);
	}
	revwin_add_code(rev->window, code, sizeof(code));
}


/**
 * This function creates the relative instruction to reverse a single
 * 64 bits word of data.
 *
 * @author Davide Cingolani
 *
 * @param win Reverse window
 * @param address The address to be reversed
 * @parm bsize The size of the single reverse block (must be 4, 8 or 16)
 *
 */
static void reverse_single_xmm(reverse_t *rev, unsigned long long address, size_t bsize) {
	unsigned int rip_relative;
	revwin_t *win;

	unsigned char revasm[22] = {
		0x48,0xb8,  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,		// movabs 0x0, %rax
		0xf3,0x0f,0x6f,0x0d,  0x0a,0x00,0x00,0x00,					// movdqu 0xa(%rip),%xmm1
		0xf3,0x0f,0x7f,0x08											// movdqu %xmm1, (%rax)
	};

	if (bsize > 128) {
		fprintf(stderr, "Incompatible data size for reverse xmm instruction\n");
		return;
	}

	win = rev->window;

	// Check whether there is enough available space to store data
	bsize = 128;
	if(!revwin_check_space(win, bsize)) {
		revwin_overflow(rev);
		win = rev->window;
	}

	// Copy the word pointed to by address
	// and store it in a proper space of the revwin's data section
	memcpy(win->data, (void *)address, bsize);

	// Computes the rip relative displacement
	// Note! 4 is the size of the last movdqu instruction to which
	// the IP will point during the actual execution.
	// For now, win->code points beyond that instruction since it is
	// not yet written
	// FIXME: problably, this does not work properly
	rip_relative = (unsigned char *)win->data - (unsigned char *)win->code - 4;

	// Update the data section ponter of reverse window
	win->data = (unsigned char *)win->data + bsize;

	// Builds the assembly reverse code with RIP-relative addressing
	memcpy(revasm+2, &address, 8);
	memcpy(revasm+14, &rip_relative, 4);

	// Actually add the code to the revwin's executable section
	if(!revwin_check_space(win, sizeof(revasm))){
		revwin_overflow(rev);
	}
	revwin_add_code(rev->window, revasm, sizeof(revasm));
}


/**
 * Generates the reversing instruction for a single address,
 * i.e. the one passed as argument.
 *
 * @author Davide Cingolani
 *
 * @param address The starting address from which to copy
 * @param size The number of bytes to reverse
 */
static void reverse_single_embedded(reverse_t *rev, unsigned long long address, size_t size) {
	unsigned long long value, value_lower;
	unsigned char *code;
	unsigned short size_code;

	unsigned char revcode_quadword[23] = {
		0x48, 0xb8, 0xda, 0xd0, 0xda, 0xd0, 0x00, 0x00, 0x00, 0x00,		// movabs $0x0, %rax
		0xc7, 0x00, 0xd3, 0xb0, 0x00, 0x00,								// movl $0x0, (%rax)
		0xc7, 0x40, 0x04, 0xb0, 0xd3, 0x00, 0x00 						// movl $0x0, 4(%rax)
	};

	unsigned char revcode_longword[16] = {
		0x48, 0xb8, 0xda, 0xd0, 0xda, 0xd0, 0x00, 0x00, 0x00, 0x00,		// movabs $0x0, %rax
		0xc7, 0x00, 0xd3, 0xb0, 0x00, 0x00								// movl $0x0, (%rax)
	};

	unsigned char revcode_word[15] = {
		0x48, 0xb8, 0xda, 0xd0, 0xda, 0xd0, 0x00, 0x00, 0x00, 0x00,		// movabs $0x0, %rax
		0x66, 0xc7, 0x00, 0xd3, 0xb0									// movw $0x0, (%rax)
	};

	unsigned char revcode_byte[13] = {
		0x48, 0xb8, 0xda, 0xd0, 0xda, 0xd0, 0x00, 0x00, 0x00, 0x00,		// movabs $0x0, %rax
		0xc6, 0x00, 0xd3												// movb $0x0, (%rax)
	};

	assert(rev != NULL);

	// if (size < 8) {
	// 	fprintf(stderr, "Incompatible data size for reverse instruction\n");
	// 	return;
	// }

	// NOTE: This may be a problem, in some particular case.
	// To lighten the overhead, we devise the reverse single instruction
	// to work with 8 bytes unregardeless of the actual size of the
	// original instruction. This should not introduce any error since
	// even though we read (and restore) more than the orignal mov size
	// the memory layout should be still consistent wrt to the environment.
	// However, there could be cases in which this assumption holds no more:
	// e.g. a case could be different thread acting on a less-8-bytes cells
	// #########################
	// FIXED by the switch case!
	// #########################

	// Get the value pointed to by 'address'
	value = value_lower = 0;
	memcpy(&value, (void *)address, size);

	switch(size) {
		case 1:
			code = revcode_byte;
			size_code = sizeof(revcode_byte);
			memcpy(code+12, &value, 1);
			break;

		case 2:
			code = revcode_word;
			size_code = sizeof(revcode_word);
			memcpy(code+13, &value, 2);
			break;

		case 4:
			code = revcode_longword;
			size_code = sizeof(revcode_longword);
			memcpy(code+12, &value, 4);
			break;

		case 8:
			code = revcode_quadword;
			size_code = sizeof(revcode_quadword);
			value_lower = ((value >> 32) & 0x0FFFFFFFF);
			memcpy(code+12, &value, 4);
			memcpy(code+19, &value_lower, 4);
			break;
	}

	// Quadword
	// code = revcode_quadword;
	// size_code = sizeof(revcode_quadword);
	// value_lower = ((value >> 32) & 0x0FFFFFFFF);
	// memcpy(code+12, &value, 4);
	// memcpy(code+19, &value_lower, 4);

	// Copy the destination address into the binary code
	// of MOVABS (first 2 bytes are the opcode)
	memcpy(code+2, &address, 8);

	// Now 'code' contains the right code to add in the reverse window
	if(!revwin_check_space(rev->window, size_code)) {
		revwin_overflow(rev);
	}
	revwin_add_code(rev->window, code, size_code);
}


/**
 * Check if the address is dirty by looking at the hash map. In case the address
 * is not present adds it and return 0.
 *
 * @author Davide Cingolani
 *
 * @param address The address to check
 *
 * @return true if the reverse MOV instruction relative to 'address' would be
 * the dominant one, false otherwise
 */
static bool check_dominance(unsigned long long address) {
	unsigned long long chunk_address;
	reverse_cache_line_t *entry;

	// Inquiry DyMeLoR's API to retrieve the address of the memory
	// area (i.e. chunk) associated with the current address
	//chunk_address = get_area(address);
	
	chunk_address = address;

	// Get the actual cache line associated with the selected cluster
	entry = get_cache_line(&cache, chunk_address);

	// Check whether the tag matches the one associated to the current address;
	// that is, it belongs to the correct chunk in cache (i.e. a chunk hit)
	// If not, simply reset the cache line to contain the new value
	if(entry->tag != get_address_tag(address)) {

		// In case of a cache miss no update were made to the cache's usefulness
		// since there is not enough information to compute anything
		// A cache miss cannot affect the cache usefulness, this not means that
		// the model is walking towards single- or chunk-based accesses

		// Reset the whole cache line
		memset(entry, 0, sizeof(reverse_cache_line_t));

		// Update the cache line tag with the current one
		entry->tag = get_address_tag(address);
	}

	// Increase the total number of chunk hits
	entry->total_hits++;
	
	// Now, verify that the address has been previously referenced or not
	if(cache_check_bit(entry, address) != 0) {
		// This is a cache hit for the current address
		return true;
	}

	// The address was not references before, therefore it is not predominate
	// by no other previous access

	// If not, update the bitmap and increase the count of distinct addresses
	// referenced so far
	cache_set_bit(entry, address);
	entry->distinct_hits++;

	// Update cache usefulness as:
	// U = distinct_hits / width
	cache.usefulness = ((double)entry->distinct_hits / (double)CACHE_LINE_SIZE);

	return false;
}

/**
 * This function will dump the whole content of a revwin,
 * or a chain of revwin if overflowed, into a dump file.
 *
 * @author Davide Cingolani
 */
static void dump_revwin(reverse_t *rev) {
	FILE *output;
	char fname[128];
	revwin_t *win;

	snprintf(fname, 128, "revwin/revwin_%p.hex", rev);

	output = fopen(fname, "w+");
	if (output == NULL) {
		printf("Unable to open dump revwin file");
		return;
	}
	
	win = rev->window;
	do {
		fwrite(win->code, REVWIN_SIZE, 1, output);
		win = win->parent;
	} while (win);

	fclose(output);
}


// ========================== APIs ========================= //

void revwin_flush_cache(void) {
	//memset(cache.lines, 0, CACHE_LINE_SIZE*sizeof(reverse_cache_line_t));
	memset(&cache, 0, sizeof(cache));
}


/**
 * Initializes a the reverse memory region of executables reverse windows. Each slot
 * is managed by a slab allocator and represents a reverse window to be executed.
 * Reverse widnows are bound to events by a pointer in their message descriptor.
 *
 * @author Davide Cingolani
 *
 * @param window_size The size of the reverse window
 */
void reverse_init(size_t window_size) {
	reverse_t *rev;

	// Allocate the structure needed by the slab allocator
	slab_chain = malloc(sizeof(struct slab_chain));
	if(slab_chain == NULL) {
		printf("Unable to allocate memory for the SLAB structure\n");
		abort();
	}

	// In this step we initialize the slab allocator in order to fast
	// handle allocation and deallocation of reverse windows which
	// will be created by each event indipendently.
	// The size passed as argument is the size of each slice the allocator
	// will return, i.e. a reverse window

	// A different value than default is used, if provided
	// NOTE: it takes into account the header of the revwin itself
	// i.e. this means that the window_size is exactly the one
	// available to store inverse code.
	if(window_size != 0) {
		assert(window_size >= REVWIN_MIN_SIZE);
		revwin_size = window_size;
	}

	slab_init(slab_chain, revwin_size + sizeof(revwin_t));
 
	// Reset the cluster cache
	revwin_flush_cache();

	// Create the reverse stack descriptor to the client
	rev = malloc(sizeof(reverse_t));
	if (rev == NULL) {
		printf("Unable to allocate a new reverse window: SLAB failure\n");
		abort();
	}
	bzero(rev, sizeof(reverse_t));
}


void reverse_fini(void) {

	// Destroy the SLAB allocator
	slab_destroy(slab_chain);

	// DEBUG:
	printf("dominated_count = %d\n", dominated_count);
}


/**
 * Set the current reverse handler to use
 */
void revwin_use(reverse_t *rev) {
	// Sanity check
	if (rev == NULL) {
		return;
	}

	// Set the current working reverse handler
	reverse = rev;
}


reverse_t * revwin_create(void) {
	reverse_t *rev;

	rev = malloc(sizeof(reverse_t));
	if(rev == NULL) {
		printf("Unable to initialize a revwin\n");
		abort();
	}

	// Create the first reverse window
	rev->window = revwin_alloc();

	// One POP %rax and one RET
	unsigned char code_closing[2] = {0x58, 0xc3};

	// Initialize the executable code area with the closing
	// instructions at the end of the actual window.
	// In this way we are sure the exection will correctly returns
	// once the whole revwin has been reverted.
	revwin_add_code(rev->window, code_closing, sizeof(code_closing));

	return rev;
}

void revwin_destroy(reverse_t *rev) {
	revwin_t *win, *parent;

	// Free each revwin still allocated
	win = rev->window;
	while(win != NULL) {
		parent = win->parent;
		revwin_free(win);
		win = parent;
	}

	free(rev);
}


/*
 * Reset the reverse window intruction pointer
 */
void revwin_reset(reverse_t *rev) {
	revwin_t *win;

	// FIXME: rivedere la procedura di reset
	return;

	// Sanity check
	if (rev == NULL) {
		// We dont care about NULL revwin
		return;
	}

	win = rev->window;

	// Resets the instruction pointer to the first byte AFTER the closing
	// instruction at the base of the window (which counts 2 bytes)
	win->code = win->code_start;
	win->data = win->data_start;
}


void unmalloc(void *address) {
	printf("Address %p will be unmalloc'd! %d\n", address);
}

void unfree(void *address) {
	printf("Address %p will be unfree'd! %d\n", address);
}


/**
 * Adds new reversing instructions to the current reverse window.
 * Genereate the reverse MOV instruction staring from the knowledge of which
 * memory address will be accessed and the data width of the write.
 * 
 * @author Davide Cingolani
 *
 * @param address The address of the memeory location to which the MOV refers
 * @param size The size of data will be written by MOV
 */
void reverse_code_generator(const unsigned long long address, const size_t size) {
	bool dominant;
	void (*reversing_function)(reverse_t *, unsigned long long, size_t);


	// Sanity check
	if(reverse == NULL) {
		printf("No revwin has been defined to use!\n");
		abort();
	}

	// unsigned long long value;
	// memcpy(&value, (void *)address, size);
	// printf("Scrittura di %d byte verso %p => [%llx]\n", (int)size, (void *)address, value);

	// Check whether the current address' update dominates over some other
	// update on the same memory region. If so, we can return earlier.
	if(enable_dominance_check) {
		dominant = check_dominance(address);
		
		if(dominant) {
			// If the current address is dominated by some other update,
			// then there is no need to generate any reversing instruction
			dominated_count++;
			return;
		}
	}

	// Act accordingly to the currrent selected reversing strategy
	if(cache.usefulness > 0.5) {
		
		reversing_function = reverse_chunk;
		
		if(strategy_id == STRATEGY_SINGLE) {
			strategy_id = STRATEGY_CHUNK;
			printf("Swith to chunk reversal (%f)\n", cache.usefulness);
		}

	} else {

		if(use_xmm) {
			reversing_function = reverse_single_xmm;
		} else {
			reversing_function = reverse_single_embedded;
		}

		if(strategy_id == STRATEGY_CHUNK) {
			strategy_id = STRATEGY_SINGLE;
			printf("Swith to single reversal (%f)\n", cache.usefulness);
		}
	}	

	// Call the actual reverse code generator
	reversing_function(reverse, address, size);
}


/**
 * Executes the code actually present in the reverse window
 *
 * @author Davide Cingolani
 *
 * @param w Pointer to the actual window to execute
 */
void execute_undo_event(reverse_t *rev) {
	unsigned char push = 0x50;
	revwin_t *win;

	// Sanity check
	if (rev == NULL) {
		return;
	}

	win = rev->window;

	// Sanity check
	if (win == NULL) {
		// There is nothing to execute, actually
		return;
	}

	printf("Execute undo event on reverse handler at <%p>\n", rev);

	// Add the complementary push %rax instruction to the top
	revwin_add_code(win, &push, sizeof(push));

	// Take a dump of the current revwin
	dump_revwin(rev);

	// Calls the reversing function
	((void (*)(void))win->code) ();
}
