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


struct oauth2plugin_strReplacementMap {
	const char* needle;
	const char* replacement;
};

static char* oauth2plugin_strReplaceAll(
	const char* haystack,
	const char* needle,
	const char* replacement
);

static char* oauth2plugin_strReplaceMap(
	const char* haystack,
	const struct oauth2plugin_strReplacementMap* map,
	size_t map_count
);

static void oauth2plugin_freeReplacementMap(
	struct oauth2plugin_strReplacementMap* map,
	size_t map_count
);

#endif // OAUTH2PLUGIN_TOOLS_H