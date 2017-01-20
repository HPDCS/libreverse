#include <stdio.h>
#include <stdlib.h>
#include <utils.h>

/**
 * Perform a hexdump of data.
 * Stores into a preallocated buffer, pointed to by the 'dump' argument,
 * the hexadecimal dump of the 'len' bytes found starting from 'addr' pointer.
 *
 * @param addr Pointer to the data buffer to dump
 *
 * @param len Number of byte to read
 */
void hexdump (void *addr, int len) {
	int i;
	int count;
	unsigned char buff[17];
	unsigned char *pc;

	if (len <= 0) {
		return;
	}

	printf ("       Address                     Hexadecimal values                      Printable     \n" );
	printf ("   ----------------  ------------------------------------------------  ------------------\n" );

	// Dumped output must be a multiple of 16
	if (len % 16 != 0) {
		count = ((len / 16) + 1) * 16;
	} else {
		count = len;
	}

	// Process every byte in the data.
	pc = (unsigned char*) addr;

	for (i = 0; i < count; i++) {

		// Multiple of 8 means mid-line (add a mid-space)
		if ((i % 8) == 0) {
			if (i != 0) {
				printf(" ");
			}
		}

		if (i < len) {
			// Multiple of 16 means new line (with line offset).
			if ((i % 16) == 0) {
				// Just don't print ASCII for the zeroth line.
				if (i != 0) {
					printf (" |%s|\n", buff);
				}

				// Output the offset.
				printf ("   (%5d) %08x ", i, i);
			}

			// Now the hex code for the specific character.
			printf (" %02x", pc[i]);

			// And store a printable ASCII character for later.
			if ((pc[i] < 0x20) || (pc[i] > 0x7e)) {
				buff[i % 16] = '.';
			} else {
				buff[i % 16] = pc[i];
			}

			buff[(i % 16) + 1] = '\0';
		}

		// Pad out last line if not exactly 16 characters.
		else {
			// Add a three-char long space for the missing character in the second column.
			printf("   ");

			// Add a printable dot for the missing character in the third column.
			buff[i % 16] = '.';
			buff[(i % 16) + 1] = '\0';
		}
	}

	// And print the final ASCII bit.
	printf ("  |%s|\n", buff);
}
