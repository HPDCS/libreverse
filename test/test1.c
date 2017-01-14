#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <time.h>

#include <pthread.h>

#include <reverse/reverse.h>
#include <reverse/ralloc.h>
#include <reverse/fmap.h>

#include "hash.h"
#include "utils.h"


#define THREAD_NUM	1		//! Number of threads to spawn

#define DATA_SIZE 1024		//! Data vector size
#define REV_SIZE 0			//! Use the reverse default value

#define WRITE_COUNT 1024	//! How many write loops on memory to do
#define WRITE_SPAN 4		//! How much coarse write granularity is
#define WRITE_PROB 0.7		//! Probability the write takes actually place on memory

#define clock() ({ \
	uint32_t lo, hi; \
	__asm__ __volatile__ ("rdtsc" : "=a" (lo), "=d" (hi)); \
	(uint64_t)(((uint64_t)hi << 32) | lo); \
})


static uint8_t bss[128] = {
	0x30, 0x91, 0x11, 0xb4, 0x60, 0xa1, 0x71, 0xaa,
	0xe9, 0x1e, 0xcf, 0x75, 0x3e, 0x1e, 0x94, 0x23,
	0x19, 0xc6, 0xfb, 0x6b, 0x08, 0x73, 0xda, 0x2b,
	0x0b, 0xd8, 0x9f, 0xce, 0x0b, 0x50, 0x16, 0x2e,
	0xd4, 0xef, 0x59, 0x98, 0x4f, 0xf4, 0x62, 0x53,
	0xe2, 0x70, 0x96, 0xfc, 0x0c, 0xf6, 0x93, 0x4a,
	0x53, 0xaa, 0x31, 0xd9, 0x9f, 0x89, 0x7a, 0x3d,
	0xc7, 0xb0, 0xf2, 0x27, 0xd3, 0xd4, 0x82, 0xbe,
	0x20, 0xe9, 0x16, 0xe1, 0x5a, 0xf6, 0x6b, 0xfb,
	0xd7, 0xc7, 0x87, 0xa3, 0x71, 0x0f, 0x1d, 0x93,
	0x22, 0x89, 0xa6, 0xa9, 0x8b, 0x6a, 0xae, 0xdd,
	0xe5, 0xd9, 0x28, 0xcb, 0x46, 0x37, 0x00, 0x9e,
	0x1d, 0x9a, 0x60, 0xbf, 0x15, 0xaa, 0xfd, 0x1f,
	0x80, 0x2f, 0xaa, 0x35, 0x8d, 0x78, 0x67, 0xcd,
	0xe5, 0x38, 0x37, 0x2d, 0x72, 0xe2, 0x28, 0xef,
	0x22, 0x92, 0x40, 0xe7, 0xff, 0xff, 0xff, 0xff
};
static uint8_t *data;

static __thread unsigned int tid;

static bool dry_run = false;
static int thread_num = THREAD_NUM;
static bool reverse = true;
static bool do_reverse = true;
static bool dump = false;
static int data_size = DATA_SIZE;
static int write_count = DATA_SIZE;
static int revwin_size = REV_SIZE;

static clock_t start_execution;
static clock_t end_execution;

/**
 * Do the hash of the .data and .bss sections
 * 
 * @author Davide Cingolani
 */
static uint64_t self_hash() {
	unsigned long long hash_bss, hash_data;
	int size;

	unsigned char *__start_data = data;
	unsigned char *__stop_data = data + data_size;
	unsigned char *__start_bss = bss;
	unsigned char *__stop_bss = bss + sizeof(bss);

	// Do the hash of .data
	size = (__stop_data - __start_data);
	printf("Compute hash of (%d bytes) in section .data starting from %p\n", size, __start_data);
	hash_data = hash(__start_data, size);

	if (dump) {
		printf("Dump of .data section (%d bytes)\n", size);
		hexdump(__start_data, size);
	}

	// Do the hash of .bss
	size = (__stop_bss - __start_bss);
	printf("Compute hash of (%d bytes) in section .bss starting from %p\n", size, __start_bss);
	hash_bss = hash(__start_bss, size);

	if (dump) {
		printf("Dump of .bss section (%d bytes)\n", size);
		hexdump(__start_bss, size);
	}

	return hash_data + hash_bss;
}

/**
 * Return true if the two hashes match
 * 
 * @author Davide Cingolani
 */
static bool check_hash(uint64_t h1, uint64_t h2) {
	return h1 == h2;
}


static void random_init() {
	uint32_t seed = (uint32_t)clock();
	srand(seed);
}

/**
 * Initializes .data section with an array of bytes randomly chosen
 *
 * @author Davide Cingolani
 */
static void data_init() {
	int i;
	int size;

	size = data_size * thread_num;

	// Initialize data vector
	data = malloc(size);
	if (data == NULL) {
		perror("Unable to allocate data vector");
	}
	memset(data, 0, size);

	for (i = 0; i < size; i += 4) {
		data[i] = rand();
	}
}

static void data_fini() {
	free(data);
}


/**
 * This function will simply setup the environment.
 * 
 * @author Davide Cingolani
 */
static void setup() {
	// Initialize reverse module
	reverse_init(revwin_size);
	ralloc_init(malloc, free);
	random_init();
	data_init();
}


/**
 * Deallocate and cleanup internal structures
 * 
 * @author Davide Cingolani
 */
static void fini() {
	reverse_fini();
	ralloc_fini();
	data_fini();
}


/**
 * Simply execute the whole reverse window in order to rollback
 * at the very beginning of the execution. Therefore the hash of data
 * sections can be recomputed again to check against the former one.
 *
 * @author Davide Cingolani
 */
static void reverse_all() {

}


/**
 * Do the actual work.
 *
 * @author Davide Cingolani
 */
void write_memory(int tid) {
	int i;

	// Write randomly chosen memory areas
	for (i = 0; i < write_count; i += WRITE_SPAN) {
		if (rand() > WRITE_PROB) {
			data[(data_size * tid) + i] = 'd';
		}
	}
}


/**
 * Worker thread function.
 *
 * @author Davide Cingolani
 */
void * worker(void *args) {
	reverse_t *handler;
	int *ptr;
	int *gptr;

	tid = *((int *)args);

	handler = revwin_create();
	revwin_use(handler);

	printf("[TH%d] Reverse handler at <%p>\n", tid, handler);

	// Function pointer to the reversible function
	void (*write_memory_instr)();
	write_memory_instr = get_instrumented_address(write_memory);

	// This is the function to instrument
	if (!dry_run) {
		printf("[TH%d] Starting random memory writes...\n", tid);

		// gptr = malloc(sizeof(int));
		// *gptr = 10;

		//printf("gptr allocated at %p => %d\n", gptr, *gptr);

		if (reverse) {
			write_memory_instr(tid);

			// ptr = rmalloc(handler, sizeof(int));
			// *ptr = 5;

			//printf("Allocated ptr = %p\n", ptr);

			//rfree(handler, ptr);
			// rfree(handler, gptr);
		}

		else {
			write_memory(tid);
		}

		if (reverse && do_reverse) {
			// Do reverse compute
			printf("[TH%d] Starting rollback on memory...\n", tid);
			execute_undo_event(handler);

			//printf("[ptr] %p => %d\n", ptr, *ptr);
		}
	} // else do nothing

	//printf("[gptr] %p => %d\n", gptr, *gptr);

	rcommit(handler);
	revwin_destroy(handler);
	//free(gptr);

	//printf("[gptr] %p => %d\n", gptr, *gptr);

	return NULL;
}

void gotplt_hooking(void);
static (*f)() = gotplt_hooking;

// ======================================================== //
int main(int argc, char **argv) {
	int id;
	char opt;
	pthread_t *thread_id;
	void *thread_errno;
	uint64_t initial_hash, final_hash;

	printf("\n");
	printf("\n");
	printf("Test name: %s\n", argv[0]);
	printf("===============================\n");

	// Parse options
	while((opt = getopt(argc, argv, "t:nfds:w:r:cxu")) != -1) {
		switch(opt) {
			case 't':
				// Set the number of thread to use
				thread_num = atoi(optarg);
				break;

			case 'n':
				// Dry run, not randomize writes
				dry_run = true;
				printf("Memory write disabled\n");
				break;

			case 'f':
				// Disable reverse undo operation
				reverse = false;
				printf("Reverse execution disabled\n");
				break;

			case 'd':
				// Disable reverse undo operation
				dump = true;
				printf("Dump enabled\n");
				break;

			case 's':
				// Set a data size to work with
				data_size = atoi(optarg);

			case 'w':
				// Set the number of writes to produce
				write_count = atoi(optarg);
				break;

			case 'r':
				// Set the number of writes to produce
				revwin_size = atoi(optarg);
				break;

			case 'c':
				// Set check dominance
				enable_dominance_check = true;
				break;

			case 'x':
				// Set check dominance
				use_xmm = true;
				break;

			case 'u':
				// Disable reverse undo operation
				do_reverse = false;
				printf("Reverse execution disabled\n");
				break;

			default:
				printf("Option not recognized and ignored (%c)!", opt);
		}
	}

	printf("Run with %d threads\n", thread_num);
	printf("Data size set to %d bytes\n", data_size);
	printf("Write count set to %d bytes\n", write_count);
	printf("Reverse window size set to %d bytes\n", revwin_size);
	printf("Check dominance is %s\n", enable_dominance_check ? "enabled" : "disabled");
	printf("XMM reversing is %s\n", use_xmm ? "enabled" : "disabled");
	printf("===============================\n\n");

	// Allocate memory to build threads
	thread_id = malloc(thread_num * sizeof(thread_id));
	if (thread_id == NULL) {
		printf("Unable to allocate thread structure\n");
		abort();
	}

	// Do the setup
	setup();

	// Compute the hash
	initial_hash = self_hash();
	printf("Initial hash of data: %lu\n", initial_hash);

	// Take time
	start_execution = clock();

	// Spawn threads
	printf("Spawning %d threads...\n", thread_num);
	for (id = 0; id < thread_num; id++) {
		pthread_create(&thread_id[id], NULL, worker, &id);
		printf("Thread %d spawned!\n", id);
	}

	printf("\n");
	fflush(stdout);

	// Wait for them to complete
	for (id = 0; id < thread_num; id++) {
		pthread_join(thread_id[id], &thread_errno);
		printf("Thread %d joined!\n", id);
	}

	// End time
	end_execution = clock();

	// Recompute the hash of data and check whether
	// initial and final ones match
	final_hash = self_hash();

	printf("Initial hash of data: %lu\n", initial_hash);
	printf("Final hash of data: %lu\n", final_hash);
	printf("\nTime elapsed: %.3f s\n",
		(((double)(end_execution - start_execution))/CLOCKS_PER_SEC)/1000);

	printf("===============================\n");
	printf("Result: ");
	if (!check_hash(initial_hash, final_hash)) {
		printf("\033[31mFAIL\033[39m\n");
	} else {
		printf("\033[32mSUCCESS\033[39m\n");
	}

	// Do the final cleanup
	free(thread_id);
	fini();

	FILE *fsproc;
	int size;
	char *data;


	fsproc = fopen("/proc/self/maps", "r");
	if(fsproc == NULL){
		printf("Error open proc file\n");
	}

	fseek(fsproc, 0L, SEEK_END);
	size = ftell(fsproc);
	rewind(fsproc);

	data = malloc(size+1);
	bzero(data, size+1);

	fread(fsproc, 1, size, data);

	fclose(fsproc);

	printf("MAPS: %s\n", data);
}