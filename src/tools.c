/**
 * tools.c
 * 
 * General helper functions
 */

#include "tools.h"


/**
 * @brief Replace all occurrences of a substring with another string.
 *
 * @param haystack    Input string to operate on.
 * @param needle      Substring to search for.
 * @param replacement Replacement text for each occurrence of @p needle.
 * @return Newly allocated string with the replacements applied or NULL on
 *         error. The caller is responsible for freeing the returned string.
 */
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
	const char* src = haystack;
	char* dst = result;
	const char* pos;
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


/**
 * @brief Replace multiple substrings within a string using a replacement map.
 *
 * Each entry in @p map specifies a needle and the corresponding replacement
 * text. The replacements are performed sequentially in the order they appear in
 * the map.
 *
 * @param haystack Input string on which replacements are performed.
 * @param map      Array of replacement rules.
 * @param map_count Number of entries in @p map.
 * @return Newly allocated string with all replacements applied or NULL on
 *         failure. Caller is responsible for freeing the returned string.
 */
char* oauth2plugin_strReplaceMap(
        const char* haystack,
        const struct oauth2plugin_strReplacementMap* map,
        size_t map_count
) {
	// Validation
	if (
		!haystack 
		|| !map
		|| map_count == 0
	) return NULL;

	// Init
	char* current_haystack = strdup(haystack);
	if (!current_haystack) return NULL;

	// Iterate over items of map
	for (
		size_t i = 0; 
		i < map_count; 
		++i
	) {
		if (
			!map[i].needle 
			|| !map[i].replacement
		) continue;

		char* new_haystack = oauth2plugin_strReplaceAll(current_haystack, map[i].needle, map[i].replacement);
		
		free(current_haystack);
		current_haystack = new_haystack;
		if (!current_haystack) return NULL;
	}

	// Return
	return current_haystack;
}


/**
 * @brief Free memory allocated for each replacement in a map.
 *
 * @param map       Array of replacement entries to free.
 * @param map_count Number of entries in @p map.
 */
void oauth2plugin_freeReplacementMap(
        struct oauth2plugin_strReplacementMap* map,
        size_t map_count
) {
	if (!map || map_count == 0) return;

	for (size_t i = 0; i < map_count; i++) {
		free((void*) map[i].replacement);
		map[i].replacement = NULL;
	}
}
