/**
 * tools.c
 * 
 * General helper functions
 */

#include "tools.h"


static char* oauth2plugin_strReplaceAll(
		const char* haystack,
		const char* needle,
		const char* replacement
) {
	// Validation	
	if (!haystack || !needle || !replacement) return NULL;

	// Get length
	const size_t haystack_length = strlen(haystack);
	const size_t needle_length = strlen(needle);
	const size_t replacement_length = strlen(replacement);
	if (needle_length == 0) return strdup(haystack);

	// Count occurrences
	size_t count = 0;
    for (const char* tmp = haystack; (tmp = strstr(tmp, needle)); tmp += needle_length)
        count++;
	if (count == 0) return strdup(haystack);

	// Calculate buffer size
    const size_t result_length = haystack_length + count * (replacement_length - needle_length) + 1;
    char* result = malloc(result_length);
    if (!result) return NULL;

	// Replace
	const char *src = haystack;
    char       *dst = result;
    const char *pos;
    while ((pos = strstr(src, needle))) {
        size_t prefix = (size_t)(pos - src);
        memcpy(dst, src, prefix);
        dst += prefix;
        memcpy(dst, replacement, replacement_length);
        dst += replacement_length;
        src = pos + needle_length;
    }
	strcpy(dst, src);

	// Return
	return result;
}