/**
 * tools.c
 * 
 * General helper functions
 */

#ifndef OAUTH2PLUGIN_TOOLS_H
#define OAUTH2PLUGIN_TOOLS_H

#include <stdlib.h>
#include <stdbool.h>
#include <string.h>


static char* oauth2plugin_strReplaceAll(
		const char* haystack,
		const char* needle,
		const char* replacement
);


#endif // OAUTH2PLUGIN_TOOLS_H