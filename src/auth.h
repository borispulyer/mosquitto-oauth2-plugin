/**
 * auth.h
 * 
 * Handle OAuth2 authentication
 */

#ifndef OAUTH2PLUGIN_AUTH_H
#define OAUTH2PLUGIN_AUTH_H

#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#include <mosquitto.h>
#include <mosquitto_broker.h>
#include <mosquitto_plugin.h>
#include <curl/curl.h>
#include "cJSON.h"

#include "options.h"
#include "tools.h"



struct oauth2plugin_CURLBuffer {
	char* data;
	size_t size;
};


/**
 * @brief Mosquitto BASIC_AUTH callback performing OAuth2 authentication.
 *
 * See auth.c for a detailed description.
 */
int oauth2plugin_callback_mosquittoBasicAuthentication(
        int event,
        void* event_data,
        void* userdata
);


/**
 * @brief Call the configured introspection endpoint.
 */
static int oauth2plugin_callIntrospectionEndpoint(
        const char* introspection_endpoint,
        const char* client_id,
        const char* client_secret,
        const char* token,
        const bool tls_verification,
        const long timeout,
        struct oauth2plugin_CURLBuffer* buffer
);


/**
 * @brief CURL write callback used by oauth2plugin_callIntrospectionEndpoint().
 */
static size_t oauth2plugin_callback_curlWriteFunction(
        void* contents,
        size_t size,
        size_t nmemb,
        void* userp
);


/**
 * @brief Validate a username against a template.
 */
static bool oauth2plugin_isUsernameValid(
        const char* username,
        const char* template,
        const struct oauth2plugin_strReplacementMap* replacement_map,
        size_t replacement_map_count
);


/**
 * @brief Check the "active" flag in an introspection response.
 */
static bool oauth2plugin_isTokenActive(
        const cJSON* introspection_response
);


/**
 * @brief Set a new username on the mosquitto client instance.
 */
static bool oauth2plugin_setUsername(
        struct mosquitto* client,
        const char* template,
        const struct oauth2plugin_strReplacementMap* replacement_map,
        size_t replacement_map_count
);


/**
 * @brief Map a verification error to a mosquitto authentication error code.
 */
static int oauth2plugin_getMosquittoAuthError(
        enum oauth2plugin_Options_verification_error error,
        const struct mosquitto* client
);

#endif // OAUTH2PLUGIN_AUTH_H