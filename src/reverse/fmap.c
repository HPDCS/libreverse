
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "fmap.h"

typedef struct _fmap {
	void *addr_original;
	void *addr_instrumented;
	char function_name[256];
} fmap;

static fmap *map;
static int num_functions;

void map_functions(int argc, char **argv, char **envp) {
	FILE *file;
	char buffer[2048];
	int idx;
	char *function_suffix;
	char *prog_name;

	prog_name = argv[0];

	printf("Mapping function for program %s\n", prog_name);
	printf("==========================================\n");

	// Create a dump containing addresses of reverse functions
	snprintf(buffer, sizeof(buffer), "readelf -aW %s | grep FUNC | grep _instr | awk '{ print $2, $8 }' > dump", prog_name);
	system(buffer);

	system("wc -l dump > num");

	file = fopen("num", "r");
	if (file == NULL)  {
		printf("Error mapping reverse function: num file open error\n");
		abort();
	}
	fscanf(file, "%d", &num_functions);
	fclose(file);

	map = malloc(num_functions * sizeof(fmap));
	if (map == NULL) {
		printf("Error mapping reverse functions: unable to allocate memory\n");
		abort();
	}
	bzero(map, num_functions * sizeof(fmap));

	file = fopen("dump", "r");
	if (file == NULL) {
		printf("Error mapping reverse functions: dump file open error\n");
		abort();
	}

	idx = 0;
	while (fgets(buffer, sizeof(buffer), file) > 0) {
		function_suffix = 0;
		
		sscanf(buffer, "%p %s", (void **)&map[idx].addr_instrumented, map[idx].function_name);
		
		function_suffix = strstr(map[idx].function_name, "_instr");
		if (function_suffix != NULL)
			*function_suffix = 0;

		idx++;
	}
	fclose(file);


	for (idx = 0; idx < num_functions; idx++) {
		snprintf(buffer, sizeof(buffer), "readelf -aW %s | grep FUNC | grep -v _instr | grep %s | awk '{ print $2 }' > dump",
			prog_name, map[idx].function_name);
		system(buffer);

		file = fopen("dump", "r");
		fgets(buffer, sizeof(buffer), file);
		sscanf(buffer, "%p", (void **)&map[idx].addr_original);
		fclose(file);
	}

	unlink("dump");
	unlink("num");

	printf("Found %d functions:\n", num_functions);

	for (idx = 0; idx < num_functions; idx++) {
		printf("Function '%s': origial at %p -- reverse at %p\n",
			map[idx].function_name,
			map[idx].addr_original,
			map[idx].addr_instrumented);
	}

	printf("Done\n");
	printf("==========================================\n");
}

__attribute__ ((section(".preinit_array"))) __typeof__(map_functions) * __map_function = map_functions;

void * get_instrumented_address(void *addr_original) {
	int idx;

	if (map == NULL) {
		printf("No function map found!\n");
		abort();
	}

	for (idx = 0; idx < num_functions; idx++) {
		if (map[idx].addr_original == addr_original) {
			return map[idx].addr_instrumented;
		}
	}

	return NULL;
}
