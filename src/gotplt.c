#include <stdio.h>

/**
 * This is the library constructor. In this function, we analyze GOT and PLT tables
 * so that we can lazily hijack library calls' hooking, creating the instrumented
 * version before returning control to the program's code.
 */
void __attribute__ ((constructor)) gotplt_hooking() {
	 printf("%s\n", __FUNCTION__);
} 
