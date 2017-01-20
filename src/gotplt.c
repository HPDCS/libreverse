/**
 * This is the library constructor. In this function, we analyze GOT and PLT tables
 * so that we can lazily hijack library calls' hooking, creating the instrumented
 * version before returning control to the program's code.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

#include <lend/lend.h>


unsigned long long *got, *gotplt, *plt;
void *original_resolver;
void *custom_resolver;
long original_resolver_size;

#define RESOLVER_SYMBOL_NAME "_dl_runtime_resolve_avx"
#define LD_LINUX_LIB "/usr/lib/ld-linux-x86-64.so.2"

#define PAGE_SIZE sysconf(_SC_PAGESIZE)

/**
 * Choose whether to call the instrumented code
 * the original one.
 */
extern void dl_selector(void);


/**
 * Retrieve the absolute address and the size of the
 * symbol name provided.
 *
 * @author Davide Cingolani
 *
 * @param name The name to look for
 * @param si A pointer to an existing struct of symbol
 * info where to place the information retrieved
 */
void lookup_symbol(const char *name, symbol_info_t **si) {

}

/**
 * This function has the task to duplicate the default runtime resolver.
 * Cloning is needed to prevent a system-wide modification.
 *
 */
void dl_resolver_clone(void) {
	FILE *file;
	char buffer[2048];

	// Inspect ELF to get the size of the _dl_runtime_resolver_avx
	snprintf(buffer, sizeof(buffer), "nm -S %s | grep -e '%s$' | awk '{ print $2 }' >> tmp", LD_LINUX_LIB, RESOLVER_SYMBOL_NAME);
	system(buffer);

	file = fopen("tmp", "r");
	if(file == NULL) {
		printf("Error cloning original_resolver\n");
		abort();
	}

	fscanf(file, "%lx", &original_resolver_size);
	fclose(file);
	unlink("tmp");

	printf("original_resolver_size = %ld\n", original_resolver_size);

	// Variable `original_resolver_size` is initialized with the proper
	// value of the size of the original resovler function.
	// Now, we have to clone the source code

	// Map an executable chunk proper of the code size
	custom_resolver = mmap(NULL, original_resolver_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	//posix_memalign((void **)&custom_resolver, PAGE_SIZE, original_resolver_size);
	if(custom_resolver == MAP_FAILED) {
		perror("Unable to allocate memory");
	}
	if(mprotect(custom_resolver, original_resolver_size, PROT_READ | PROT_WRITE | PROT_EXEC) < 0) {
		perror("Unable to set memory permissions\n");
	}

	// Get the address of the original resolver
	original_resolver = (void *)*(gotplt+2);

	// Clone the code
	memcpy(custom_resolver, original_resolver, original_resolver_size);

	// Fixup the relative call to _dl_fixup
	unsigned char *instr = custom_resolver;
	while(*instr != 0xe8) {
		instr += length_disasm(instr, MODE_X64);
	}

	// FIXME: da raffinare
	long long offset = original_resolver - custom_resolver;
	int dl_fixup_ptr;
	memcpy(&dl_fixup_ptr, instr+1, 4);
	dl_fixup_ptr += offset;
	memcpy(instr+1, &dl_fixup_ptr, 4);


	// Hack the code of custom resover
	instr = custom_resolver;
	while(*instr != 0xf2) {
		instr += length_disasm(instr, MODE_X64);
	}

	unsigned char code[12] = {
		0x48, 0xb8, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00,
		0xff, 0xe0
	};

	offset = (unsigned long long)dl_selector;
	memcpy(code+2, &offset, 8);
	memcpy(instr, code, sizeof(code));

}


void gotplt_resolve_address(int argc, char **argv, char **envp) {
	FILE *file;
	char buffer[2048];
	char *prog_name;

	prog_name = argv[0];

	printf("Resolvig GOT PLT tables fo program %s\n", prog_name);
	printf("==========================================\n");

	// Create a dump containing addresses of gotplt table
	snprintf(buffer, sizeof(buffer), "readelf -SW %s | grep ' .got ' | awk '{ print $4; }' > got", prog_name);
	system(buffer);

	// Create a dump containing addresses of gotplt table
	snprintf(buffer, sizeof(buffer), "readelf -SW %s | grep '.got.plt' | awk '{ print $4; }' > gotplt", prog_name);
	system(buffer);

	// Create a dump containing addresses of gotplt table
	snprintf(buffer, sizeof(buffer), "readelf -SW %s | grep ' .plt ' | awk '{ print $4; }' > plt", prog_name);
	system(buffer);
	
	file = fopen("got", "r");
	if(file == NULL) {
		printf("Unable to resolve GOTPLT!\n");
		abort();
	}

	bzero(buffer, sizeof(buffer));
	fscanf(file, "%llx", &got);
	fclose(file);
	unlink("got");


	file = fopen("gotplt", "r");
	if(file == NULL) {
		printf("Unable to resolve GOTPLT!\n");
		abort();
	}

	bzero(buffer, sizeof(buffer));
	fscanf(file, "%llx", &gotplt);
	fclose(file);
	unlink("gotplt");


	file = fopen("plt", "r");
	if(file == NULL) {
		printf("Unable to resolve GOTPLT!\n");
		abort();
	}

	bzero(buffer, sizeof(buffer));
	fscanf(file, "%llx", &plt);
	fclose(file);
	unlink("plt");

	printf("got at %p\n", got);
	printf("gotplt at %p\n", gotplt);
	printf("plt at %p\n", plt);

	printf("Done\n");
	printf("==========================================\n");

	dl_resolver_clone();
}
__attribute__ ((section(".preinit_array"))) __typeof__(gotplt_resolve_address) *__gotplt_resolve_address = gotplt_resolve_address;




void __attribute__ ((constructor)) gotplt_hooking(void) {
	// Change the absolute address of the resolver
	// NOTE: this operation must be done after the resolver code
	// has been cloned and patched, otherwhise, we incur into the
	// call to an empty and inconsistent resolver
	*(gotplt+2) = (unsigned long long)custom_resolver;
}
