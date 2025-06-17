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

static size_t oauth2plugin_callback_curlWriteFunction(
	void* contents, 
	size_t size, 
	size_t nmemb, 
	void* userp
);

static int oauth2plugin_getIntrospectionResponse(
	const char* introspection_endpoint,
	const char* client_id,
	const char* client_secret,
	const char* token,
	const bool verify_tls_certificate,
	const long timeout,
	struct oauth2plugin_CURLBuffer* buffer
);

static bool oauth2plugin_isTokenValid(
	const char* introspection_response,
	const char* username
);

int oauth2plugin_callback_mosquittoBasicAuthentication(
	int event, 
	void* event_data, 
	void* userdata
);

#endif // OAUTH2PLUGIN_AUTH_H