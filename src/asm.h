#pragma once

#define	hinternal()	fprintf(stderr, "%s: internal error at line %d\n", __FILE__, __LINE__)
