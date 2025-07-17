/**
 * tools.h
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

/**
 * @brief Replace all occurrences of @p needle with @p replacement in @p haystack.
 *
 * @param haystack    Input string.
 * @param needle      Substring to search for.
 * @param replacement Replacement string.
 * @return Newly allocated string with replacements or NULL on failure.
 */
static char* oauth2plugin_strReplaceAll(
        const char* haystack,
        const char* needle,
        const char* replacement
);

/**
 * @brief Perform multiple substring replacements using a map.
 *
 * @param haystack Input string to operate on.
 * @param map      Array of replacement entries.
 * @param map_count Number of entries in @p map.
 * @return Newly allocated string with all replacements applied or NULL.
 */
char* oauth2plugin_strReplaceMap(
        const char* haystack,
        const struct oauth2plugin_strReplacementMap* map,
        size_t map_count
);

/**
 * @brief Free memory allocated for the replacement strings in a map.
 *
 * @param map       Array of replacement entries.
 * @param map_count Number of entries in @p map.
 */
void oauth2plugin_freeReplacementMap(
        struct oauth2plugin_strReplacementMap* map,
        size_t map_count
);

#endif // OAUTH2PLUGIN_TOOLS_H