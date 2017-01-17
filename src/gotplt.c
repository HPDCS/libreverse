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
#include <assert.h>

#include <lend/lend.h>
#include <gotplt.h>
#include <asm/insn.h>
#include <asm/src/x86/x86.h>


#define unlikely(x)	__builtin_expect(x, 0)
#define likely(x)	__builtin_expect(x, 1)


#define RESOLVER_SYMBOL_NAME "_dl_runtime_resolve_avx"
#define LD_LINUX_LIB "/usr/lib/ld-linux-x86-64.so.2"
#define PAGE_SIZE sysconf(_SC_PAGESIZE)


unsigned long long *got, *gotplt, *plt;

char *original_resolver;
char *custom_resolver;
long original_resolver_size;

symbol_info_t *symtab = NULL;
int num_syms;

/**
 * Choose whether to call the instrumented code
 * the original one.
 */
extern void dl_selector(void);
extern void dl_trampoline(void);
extern char *jmp_to_origial_api;
extern int dl_trampoline_size;


/**
 * Retrieve the absolute address and the size of the
 * symbol name provided.
 *
 * @author Davide Cingolani
 *
 * @param addr The absolute address to look for
 * @param si A pointer to an existing struct of symbol
 * info where to place the information retrieved
 */
symbol_info_t * lookup_symbol(const void *addr) {
	int idx;
	// int len;
	symbol_info_t *sym;

	// for(idx = 0; idx < num_syms; idx++) {
	// 	if(symtab[idx].address == addr) {
	// 		*si = symtab + idx;
	// 		return 0;
	// 	}
	// }

	sym = symtab;
	while(sym) {
		if(sym->address == addr) {
			return sym;
		}
		sym = sym->next;
	}

	return NULL;
}


/**
 * Instrument the code by relying on a mix of length
 * disassembler and x86-disassembler.
 */
void dl_instrumenter(void *symaddr) {
	unsigned char *code, *trampoline;
	unsigned int size, size_trampoline;
	unsigned long int pos;
	symbol_info_t *si;
	insn_info_x86 instr;
	int flags;
	char opcode;

	printf("Look for symbol at address <%p>\n", symaddr);

	// Lookup the target API symbol from the knowledge
	// of its absolute address provided by the dl_lookup_symbol_x
	// function called previously by the DL system framework
	si = lookup_symbol(symaddr);
	if(si == NULL) {
		fprintf(stderr, "Unable to lookup symbol at <%p>\n", symaddr);
		abort();
	}

	// Once we know the size of the API function to call
	// we mmap new pages to store the instrumented code.
	// Simingly to the PLT structure, we append ad-hoc
	// trampoline snippets to the end of the mmap'ed memory

	// NOTE: in order to allocate enough memory, we assume
	// the worst case where all the instruction could instrumented
	// times the size of the trampoline snippet appended
	size_trampoline = dl_trampoline_size;
	size = si->size * size_trampoline;
	code = mmap(0, size, PROT_READ | PROT_WRITE | PROT_EXEC ,MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if(code == MAP_FAILED) {
		fprintf(stderr, "Error memory mapping\n");
		abort();
	}

	// Initialize the trampoline pointer just after the end of the
	// API original code in the new mmap so that to generate trampoline
	// code snippets each time needed
	trampoline = code + si->size;

	// Copy the orignal API's code to the instrumeted one
	memcpy(code, symaddr, size);

	printf("Found symbol at <%p> '%s' of size %d\n", si->address, si->name, si->size);

	flags = 0;

	// === Walk the code ===
	// In this step we have to do the following steps:
	//   *1. Copy the instruction to the instrumented API (new mmap'ed page)*
	//   2. At the same time, check if the instruction is a MEMWR
	//      and in that case replace it with a JMP to the ad-hoc trampoline
	//      code snippet (PLT-like)
	//   3. Write a proper trampoline snippet at the end of the custom API
	//      and rewrite the original MOV into it
	while(pos < size) {
		pos += length_disasm(code, MODE_X64);
		opcode = *code;
		
		// Check if a REX prefix is met and skip it
		// in order to read the primary opcode
		if((opcode >> 4) == 0x40)
			opcode = *(code+1);

		// Look for a possible MOV opcode
		if((opcode & 0xf0) == (0x80 | 0xA0 | 0xB0 | 0xC0)) {

			// Disassemble the instruction iteself
			x86_disassemble_instruction(code, &pos, &instr, flags);

			printf("Found %s\n", instr.mnemonic);

			// The MOV instruction writes on memory
			if(IS_MEMWR(&instr)) {
				printf("Found a MEMWR\n");

				// Replace it with the jump to the ad-hoc trampoline
				// to append at the end of the instrumented API code

				// Get the target address and the write size
				// instr.flags

				// displacement + (base + index * scale)
				char write_address[5];
				int write_size;
				int offset;

				*write_address = instr.sib;
				*(write_address+1) = (int)instr.disp;
				write_size = instr.span;

				// Write a new trampoline snippet
				memcpy(trampoline, dl_trampoline, size_trampoline);

				// Reslove actual values
				offset = trampoline - code;
				memcpy(trampoline+2, &write_address, sizeof(write_address));
				memcpy(trampoline+8, &write_size, sizeof(write_size));
				memcpy(jmp_to_origial_api+1, &offset, sizeof(offset));

				//unsigned char jmp[5] = {0xe9, 0x00, 0x00, 0x00, 0x00};

				assert(instr.insn_size >= 5);
				
				offset = -offset;
				memset(code, 0, instr.insn_size);
				*code = 0xe9;
				memcpy(code+1, &offset, sizeof(offset));

				trampoline += size_trampoline;
			}
		}
	}
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
	snprintf(buffer, sizeof(buffer), "nm -S %s | grep -e '%s$' | awk '{ print $2 }' >> /tmp/size", LD_LINUX_LIB, RESOLVER_SYMBOL_NAME);
	system(buffer);

	file = fopen("/tmp/size", "r");
	if(file == NULL) {
		printf("Error cloning original_resolver\n");
		abort();
	}

	fscanf(file, "%lx", &original_resolver_size);
	fclose(file);
	unlink("/tmp/size");

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

	// Create a dump containing addresses of got table
	snprintf(buffer, sizeof(buffer), "readelf -SW %s | grep ' .got ' | awk '{ print $4; }' >> /tmp/gotplt", prog_name);
	system(buffer);

	// Create a dump containing addresses of gotplt table
	snprintf(buffer, sizeof(buffer), "readelf -SW %s | grep '.got.plt' | awk '{ print $4; }' >> /tmp/gotplt", prog_name);
	system(buffer);

	// Create a dump containing addresses of plt table
	snprintf(buffer, sizeof(buffer), "readelf -SW %s | grep ' .plt ' | awk '{ print $4; }' >> /tmp/gotplt", prog_name);
	system(buffer);
	
	file = fopen("/tmp/gotplt", "r");
	if(file == NULL) {
		printf("Unable to resolve GOTPLT!\n");
		abort();
	}

	fscanf(file, "%llx", &got);
	fscanf(file, "%llx", &gotplt);
	fscanf(file, "%llx", &plt);
	fclose(file);
	unlink("/tmp/gotplt");


	printf("got at %p\n", got);
	printf("gotplt at %p\n", gotplt);
	printf("plt at %p\n", plt);

	printf("Done\n");
	printf("==========================================\n");

	dl_resolver_clone();
}
__attribute__ ((section(".preinit_array"))) __typeof__(gotplt_resolve_address) *__gotplt_resolve_address = gotplt_resolve_address;


void dump_symbols(int argc, char **argv, char **envp) {
	FILE *deps, *proc, *syms;
	char buffer[4096];
	char *prog_name;
	char dep_name[1024];
	unsigned long long base_address;
	symbol_info_t *sym;

	prog_name = argv[0];

	// snprintf(buffer, sizeof(buffer),
	// 	//"for lib in $(ldd %s | awk '{ print $3; }' | sed '/^$/d'); do\n"
	// 	"for lib in $(ldd %s | head -n-1 | tail -n+2 | awk '{ print $3 \" \" $4; }'); do\n"
 //    	"nm -Snfp --defined-only $lib | awk '{ print $1 \" \" $3 \" \" $4 }' >> syms\n"
	// 	"done",
	// 	prog_name);
	//system("wc -l syms > lines");

	// Get lib dependencies
	snprintf(buffer, sizeof(buffer),
		"ldd %s | head -n-1 | tail -n+2 | awk '{ print $3; }' > /tmp/deps", prog_name);
	system(buffer);

	deps = fopen("/tmp/deps", "r");
	if(deps == NULL) {
		printf("Error to get deps\n");
		abort();
	}

	proc = fopen("/proc/self/maps", "r");
	if(proc == NULL) {
		printf("Error to open procfs\n");
		abort();
	}

	sym = symtab = calloc(1, sizeof(symbol_info_t));

	// For all dependencies
	while(fscanf(deps, "%s", buffer) != EOF) {

		// Resolve possible symbolic links
		if(realpath(buffer, dep_name) == NULL) {
			fprintf(stderr, "Error resolving symbolic link '%s'\n", buffer);
			abort();
		}

		// Get the relative info from proc file
		rewind(proc);
		while(fgets(buffer, sizeof(buffer), proc) != NULL) {
	        int len = strlen(dep_name);
	        char *ptr = buffer + strlen(buffer) - 1;

	        for(;*ptr != ' '; ptr--);
	        ptr++;

	        if(!strncmp(ptr, dep_name, len)) {
	            base_address = (void *) strtol(buffer, NULL, 16);
	            break;
	        }
    	}

    	snprintf(buffer, sizeof(buffer),
			"nm -SDnfp --defined-only '%s' | grep -e ' [tT] ' | awk '{ print $1 \" \" $3 \" \" $4 }' > /tmp/syms",
			dep_name);
		system(buffer);

		syms = fopen("/tmp/syms", "r");
		if(syms == NULL) {
			printf("Error to get syms\n");
			abort();
		}

		// sym = malloc(sizeof(symbol_info_t));
		// sym->next = 0;
		
		// if(symtab == NULL)
		// 	symtab = sym;

		// while(fscanf(syms, "%s %lx %lx\n", sym->name, (sym->address + base_address), sym->size)) {
		// 	sym->next = malloc(sizeof(symbol_info_t));
		// 	sym = sym->next;
		// 	sym->next = 0;
		// }

		while(fgets(buffer, sizeof(buffer), syms) != NULL) {

			sscanf(buffer, "%s %lx %lx", sym->name, &sym->address, &sym->size);
			sym->address += base_address;

			sym->next = calloc(1, sizeof(symbol_info_t));
			sym = sym->next;
		}

		fclose(syms);
	}

	fclose(deps);
	fclose(proc);

	unlink("/tmp/syms");
	unlink("/tmp/deps");

	// // For each dependency read its symbols
	// int i;
	// for(i = 0; i<idx; i++) {
	// 	snprintf(buffer, sizeof(buffer),
	// 		"nm -Snfp --defined-only $lib | awk '{ print $1 \" \" $3 \" \" $4 }' >> tmp\n",
	// 		deps[i].name);
	// 	system(buffer);
	// 	rewind(file);


	// }


	// file = fopen("lines", "r");
	// if(file == NULL) {
	// 	printf("Error to get symbols\n");
	// 	abort();
	// }

	// fscanf(file, "%d", &num_syms);

	// fclose(file);
	// unlink("lines");


	// printf("Found %d symbols\n", num_syms);

	// symtab = calloc(num_syms, sizeof(symbol_info_t));
	// if(symtab == NULL) {
	// 	printf("Error allocating symbol info structure\n");
	// 	abort();
	// }

	// file = fopen("syms", "r");
	// if(file == NULL) {
	// 	printf("Error dumping symbols\n");
	// 	abort();
	// }

	// int idx;
	// for(idx = 0; idx < num_syms; idx++) {
	// 	fscanf(file, "%s %lx %lx\n", &symtab[idx].name, &symtab[idx].address, &symtab[idx].size);
	// }

	// fclose(file);
	// unlink("syms");
}
__attribute__ ((section(".preinit_array"))) __typeof__(dump_symbols) *__dump_symbols = dump_symbols;


void __attribute__ ((constructor)) gotplt_hooking(void) {
	// Change the absolute address of the resolver
	// NOTE: this operation must be done after the resolver code
	// has been cloned and patched, otherwhise, we incur into the
	// call to an empty and inconsistent resolver
	*(gotplt+2) = (unsigned long long)custom_resolver;
}
