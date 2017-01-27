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

#define RESOLVER_GOT_OFFSET 2
#define GOT_LIB_SLOT(table, index) ((table)+(index)+RESOLVER_GOT_OFFSET+1)

#undef DEBUG

unsigned long long *got, *gotplt, *plt;
size_t got_size, gotplt_size, plt_size;

char *original_gotplt;

char *original_resolver;
char *custom_resolver;
long original_resolver_size;

symbol_info_t *symtab = NULL;
int num_syms;

/**
 * Choose whether to call the instrumented code
 * the original one.
 */
extern void dl_prepare_resolver(void);
extern void dl_trampoline(void);
extern void dl_selector(void);

extern int trmp_lea_offset;
extern int trmp_mov_offset;
extern int trmp_ret_offset;
extern int trmp_orig_offset;
extern int address_original;
extern int address_instrumented;

extern int dl_trampoline_size;
extern int dl_selector_size;

static unsigned char *fake_got;
static unsigned char *fake_got_curr;

__thread int _dso_mode;


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
static symbol_info_t * lookup_symbol(const void *addr) {
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
void * dl_instrumenter(void *symaddr, int index) {
	unsigned char *code, *trampoline, *selector;
	unsigned char *lib;
	unsigned int size, size_trampoline;
	unsigned long int len, _dontcare;
	symbol_info_t *si;
	insn_info_x86 instr;	// Current instruction
	int dflags;			// Disassembler flags
	char opcode;		// Opcode of the current instruction
	int old_mode;		// Library operational mode before instrumenter

	char write_address[6];
	int write_size;
	int offset;

	// The instrumenter MUST be executed in MODE_PLATFORM
	old_mode = _dso_mode;
	_dso_mode = MODE_PLATFORM;

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
	size = (si->size * size_trampoline);
	code = mmap(0, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if(code == MAP_FAILED) {
		fprintf(stderr, "Error memory mapping\n");
		abort();
	}
	lib = code;

	// Initialize the trampoline pointer just after the end of the
	// API original code in the new mmap so that to generate trampoline
	// code snippets each time needed
	trampoline = (code + si->size);

	// Copy the orignal API's code to the instrumeted one
	memcpy(code, symaddr, si->size);

	printf("Found symbol at <%p> '%s' of size %d\n", si->address, si->name, si->size);

	dflags = 0;
	//memset(&instr, 0, sizeof(insn_info_x86));

	// === Walk the code ===
	// We have to do the following steps:
	//   1. Copy the instruction to the instrumented API (new mmap'ed page)
	//   2. At the same time, check if the instruction is a MEMWR
	//      and in that case replace it with a JMP to the ad-hoc trampoline
	//      code snippet (PLT-like)
	//   3. Write a proper trampoline snippet at the end of the custom API
	//      and rewrite the original MOV into it
	//   4. Resolve all the RIP-relative references wrt the new code address
	while(code < (lib + size)) {
		len = length_disasm(code, MODE_X64);
		opcode = *code;
		_dontcare = 0;
		
		// Check if a REX prefix is met and skip it to read the primary opcode
		if((opcode >> 4) == 0x4) {
			opcode = *(code+1);
		}

		// Look for a possible MOV opcode
		register char op = opcode & 0xf0;
		// FIXME: ottimizzare!!
		// FIXME: rimuovere branch forzata
		if(1 || op == 0x80 || op == 0xA0 || op == 0xB0 || op == 0xC0) {

			printf("possible\n");

			// Disassemble the instruction
			x86_disassemble_instruction(code, &_dontcare, &instr, dflags);

			// Check whether MOV instruction writes on memory
			if(IS_MEMWR(&instr)) {
		instrument_memwr:
				printf("Found MEMWR mov at <%p> (originally at <%p> '%s')\n", code, symaddr+(int)(code-lib), si->name);

				// NOTE
				// In order to recompute the target address we have to keep in mind
				// that this code is not actually in execution therefore, we cannot
				// to simply solve the addressing to get the write address; instead
				// we have to let the runtime assembly do it for us.
				// So, the idea is to embed the addressing mode (Mod/RM + SIB) within
				// a new lea instruction to pass the result to our trampoline;
				// unfortunatly this operation cannot be performed wholly automatically
				// since not all the opcode treats Mod/RM operands in the same order...

				// ----------------------------------------------------------------------
				// | Prefix | Opcode | Mod/RM | SIB |   Displacement   |   Immediate    |
				// ----------------------------------------------------------------------
				// | 1 byte | 1 byte | 1 byte |1byte|     4 byte       |     4 byte     |

				int idx = 1;

				// Clone Mod/RM byte and force destination register as %rdi (7)
				// FIXME: ottimizzare!!
				memset(write_address, 0x90, sizeof(write_address));
				*write_address = (instr.modrm | (0x7 << 3));

				// Check whether the RM flag indicates SIB byte presence
				if((instr.modrm & 0x7) == 0x4) {
					*(write_address+(idx++)) = instr.sib;
				}

				switch(instr.modrm >> 6){
					case 1:
						*(write_address+idx) = (char)instr.disp;
						break;

					case 2:
						*(write_address+idx) = (int)instr.disp;
						break;
				}

				write_size = instr.span;

				// Write a new trampoline snippet from the model
				memcpy(trampoline, dl_trampoline, size_trampoline);

				// Reslove actual values
				memcpy(get_code_ptr(trampoline, trmp_lea_offset), &write_address, sizeof(write_address));
				memcpy(get_code_ptr(trampoline, trmp_mov_offset), &write_size, sizeof(write_size));

				// Clone the original MOV instruction right in the trampoline snippet
				memcpy(get_code_ptr(trampoline, trmp_orig_offset), &instr.insn, instr.insn_size);

				// If the original instruction is not bug enough we have to use the following
				// one, however this could be another memwr itself..therefore we forward
				// instrument also the second one, here, in place
				if(unlikely(instr.insn_size < 5)) {
					x86_disassemble_instruction(code+len, &_dontcare, &instr, dflags);
					
					// If the following instruction is a memwr, we do the instrumentation
					// step again, takeing into account the length of both the instructions.
					// Trampoline is yet updated, therefore when we re-instrument we will have
					// another trampoline in cascade. The only thing we have to guarantee in 
					// the previous trampoline is to jump to the following one, but this is
					// guaranteed by the fact that the template has a relative offset of zero
					if(IS_MEMWR(&instr)) {
						// Ready to copy another template in the next right slot
						trampoline += size_trampoline;

						goto instrument_memwr;
					}

					// here `len` holds the length of the previous instruction
					memcpy(get_code_ptr(trampoline, trmp_orig_offset+len), &instr.insn, instr.insn_size);

					// Update the length so that the cycle will take into account the fact we
					// parsed also the following instruction
					len += instr.insn_size;
				}

				// Ready to copy another template in the next right slot
				trampoline += size_trampoline;

				// Embed the relative offset towards the orignal `code` point--which is not
				// incremented in the case of chained trampolines.
				// NOTE: the pointer `trampoline-size_trampline` is CORRECT provided that
				// we pre-increment the trampoline pointer before the check of a subsequent
				// memwr instruction; in this way we do not have to handle the increment
				// twice: one in whitin the `if` and one just after.
				offset = (trampoline - code) + len;
				memcpy(get_code_ptr(trampoline, trmp_ret_offset), &offset, sizeof(offset));

				// Overwrite the value of the original instruction with
				// the jump to the trampoline---which performs this instruction
				// and returns the control next to it in the original code
				//assert(instr.insn_size >= 5);
				
				// Now, replace memwr mov with a jump to the ad-hoc trampoline
				// appended at the end of the API code.
				offset = -offset;
				// FIXME: ottimizzare!!
				memset(code, 0x90, len);
				*code = 0xe9;
				memcpy(code+1, &offset, sizeof(offset));
			}
		}

		// Realign RIP-relative addressing
		// NOTE: `has_rip_relative` macro tells whether the last instrution parsed by
		// lend does rely on rip relative addressing mode or not
		if(has_rip_relative()) {
			// printf("Found RIP-relative instruction '%s' <%p>\n", instr.mnemonic, code);
			x86_disassemble_instruction(code, &_dontcare, &instr, dflags);

			// Fix the relative displacement
			// The new offset can be computed as the previous incremented
			// by the difference by the two starting address of the original
			// API with the patched one
			offset = instr.disp + ((unsigned char *)symaddr - lib);
			memcpy(code+instr.disp_offset, &offset, sizeof(int));
		}

		// Step forward to the next instruction
		code += len;
	}


	// Instrumented code has to be placed into the fake got
	// in order to call the proper function depending on the
	// execution mode flag.
	// This got table must be generated by the instrumenter
	// wiring the proper absolute addresses into it.
	selector = mmap(0, dl_selector_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	
	// Write a new selector snippet from the model
	memcpy(selector, dl_selector, dl_selector_size);

	// Generate and wire addresses
	memcpy(get_code_ptr(selector, address_original), &symaddr, sizeof(void *));
	memcpy(get_code_ptr(selector, address_instrumented), &lib, sizeof(void *));

	assert(fake_got != NULL);

	// Fixup the fake GOT and divert the original one to this
	memcpy(fake_got_curr, selector, dl_selector_size);
	*GOT_LIB_SLOT(gotplt, index) = selector;

	// Update the fake GOT table pointer for the next library
	fake_got_curr += dl_selector_size;

	// Restore operational mode
	_dso_mode = old_mode;

	return selector;
}


/**
 * This function has the task to duplicate the default runtime resolver.
 * Cloning is needed to prevent a system-wide modification.
 *
 */
static void patch_resolver(void) {
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

	// The resolver must call the instrumenter which is in
	// charge to fixup manually the GOT table with a proper
	// code snippet which switch the execution mode accordingly
	// to the mode library flag
	offset = (unsigned long long)dl_prepare_resolver;
	memcpy(code+2, &offset, 8);
	memcpy(instr, code, sizeof(code));

}


static void gotplt_resolve_address(int argc, char **argv, char **envp) {
	FILE *file;
	char buffer[2048];
	char *prog_name;

	prog_name = argv[0];

	printf("Resolvig GOT PLT tables fo program %s\n", prog_name);
	printf("==========================================\n");

	// Create a dump containing addresses of got table
	snprintf(buffer, sizeof(buffer), "readelf -SW %s | grep ' .got ' | awk '{ print $4 \" \" $6; }' >> /tmp/gotplt", prog_name);
	system(buffer);

	// Create a dump containing addresses of gotplt table
	snprintf(buffer, sizeof(buffer), "readelf -SW %s | grep '.got.plt' | awk '{ print $4 \" \" $6; }' >> /tmp/gotplt", prog_name);
	system(buffer);

	// Create a dump containing addresses of plt table
	snprintf(buffer, sizeof(buffer), "readelf -SW %s | grep ' .plt ' | awk '{ print $4 \" \" $6; }' >> /tmp/gotplt", prog_name);
	system(buffer);
	
	file = fopen("/tmp/gotplt", "r");
	if(file == NULL) {
		printf("Unable to resolve GOTPLT!\n");
		abort();
	}

	fscanf(file, "%llx %d", &got, &got_size);
	fscanf(file, "%llx %d", &gotplt, &gotplt_size);
	fscanf(file, "%llx %d", &plt, &plt_size);

	fclose(file);
	unlink("/tmp/gotplt");


	fake_got = mmap(0, ((gotplt_size / sizeof(long long)) * dl_selector_size), PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if(fake_got == MAP_FAILED) {
		fprintf(stderr, "Error on memory mapping\n");
		abort();
	}
	fake_got_curr = fake_got;

	printf("got at %p\n", got);
	printf("gotplt at %p\n", gotplt);
	printf("plt at %p\n", plt);

	// Dump content of the original GOTPLT
	original_gotplt = mmap(0, gotplt_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if(original_gotplt == MAP_FAILED) {
		fprintf(stderr, "Error on memory mapping\n");
		abort();
	}
	memcpy(original_gotplt, gotplt, gotplt_size);

	printf("Done\n");
	printf("==========================================\n");

}
// __attribute__ ((section(".preinit_array"))) __typeof__(gotplt_resolve_address) *__gotplt_resolve_address = gotplt_resolve_address;


static void symbol_import(int argc, char **argv, char **envp) {
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

	// Head of the symbol list
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
			"nm -SP --defined-only '%s' | grep -e ' [tTW] ' | awk '{ print $1 \" \" $3 \" \" $4 }' > /tmp/syms",
			// "nm -SDP '%s' | awk '{ print $1 \" \" $3 \" \" $4 }' > /tmp/syms",
			dep_name);
		system(buffer);

		syms = fopen("/tmp/syms", "r");
		if(syms == NULL) {
			printf("Error to get syms\n");
			abort();
		}

		// Import each symbol of the dependancy
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

	// FIXME: debug only!!!
#ifdef DEBUG
	sym = symtab;
	while(sym) {
		printf("%s at <%p>\n", sym->name, sym->address);
		sym = sym->next;
	}
#endif

}
// __attribute__ ((section(".preinit_array"))) __typeof__(dump_symbols) *__dump_symbols = dump_symbols;


/**
 * Initialize the environment for the libreverse to work properly.
 * In particular, it must import all the external symbols which can
 * be loaded at runtime and divert the execution towards a custom
 * DSO resolver instead of the original one.
 * This function should be invoked prior of the _start entry point
 *
 * NOTE: Note that the original dl_fixup and the inner dl_lookup_symbol
 * functions are maintained in their original suite.
 *
 * @author Davide Cingolani
 */
static void _libreverse_preinit(int argc, char **argv, char **envp) {
	symbol_import(argc, argv, envp);
	gotplt_resolve_address(argc, argv, envp);
	patch_resolver();
}
__attribute__ ((section(".preinit_array"))) __typeof__(_libreverse_preinit) *__libreverse_preinit = _libreverse_preinit;


void __attribute__ ((constructor)) gotplt_hooking(void) {
	// Just before to run the real program we need to reinit the GOTPLT
	// otherwise the yet resolved API will override the actual patch
	memcpy(gotplt, original_gotplt, gotplt_size);

	// Change the absolute address of the resolver
	// NOTE: this operation must be done after the resolver code
	// has been cloned and patched, otherwhise, we incur into the
	// call to an empty and inconsistent resolver
	*(gotplt+RESOLVER_GOT_OFFSET) = (unsigned long long)custom_resolver;
}


void switch_operational_mode(int flags) {
	//assert(!(flags & -0x3));

	_dso_mode = flags;

	printf("Switch to %s mode", _dso_mode == MODE_PLATFORM ? "platform" : "reversible");
}
