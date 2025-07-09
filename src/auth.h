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



struct oauth2plugin_CURLBuffer {
	char* data;
	size_t size;
};

static int oauth2plugin_getMosquittoAuthError(
	enum oauth2plugin_Options_verification_error error,
	const struct mosquitto* client
);

static bool oauth2plugin_isUsernameValid_preOAuth2(
	const char* username,
	const enum oauth2plugin_Options_username_validation username_validation,
	const char* username_validation_template
);

static bool oauth2plugin_isUsernameValid_postOAuth2(
	const char* username,
	const cJSON* introspection_response,
	const enum oauth2plugin_Options_username_validation username_validation,
	const char* username_validation_template
);

static bool oauth2plugin_isTokenActive(
	const cJSON* introspection_response
);

static bool oauth2plugin_setUsername(
	struct mosquitto* client,
	const cJSON* introspection_response,
	const enum oauth2plugin_Options_username_replacement username_replacement,
	const char* username_replacement_template
);

static size_t oauth2plugin_callback_curlWriteFunction(
	void* contents, 
	size_t size, 
	size_t nmemb, 
	void* userp
);

static int oauth2plugin_callIntrospectionEndpoint(
	const char* introspection_endpoint,
	const char* client_id,
	const char* client_secret,
	const char* token,
	const bool tls_verification,
	const long timeout,
	struct oauth2plugin_CURLBuffer* buffer
);

int oauth2plugin_callback_mosquittoBasicAuthentication(
	int event, 
	void* event_data, 
	void* userdata
);

#endif // OAUTH2PLUGIN_AUTH_H