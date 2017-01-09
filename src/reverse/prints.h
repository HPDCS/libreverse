#ifndef _PRINT_H_
#define _PRINT_H_

#define printd(msg) while(0) {\
	if(enable_debug) {\
		printf(msg);\
	}\
}

#endif //_PRINT_H_
