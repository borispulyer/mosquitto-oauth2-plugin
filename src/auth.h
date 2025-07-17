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
 * @brief Mosquitto BASIC_AUTH callback used for OAuth2 authentication.
 *
 * This function is registered with the broker and executed for each incoming connection attempt. It performs validation of the MQTT username/password combination by querying the configured OAuth2 introspection endpoint.
 *
 * @param event			Event type (unused, expected to be MOSQ_EVT_BASIC_AUTH).
 * @param event_data	Pointer to struct mosquitto_evt_basic_auth provided by Mosquitto.
 * @param userdata		Plugin specific data pointer supplied during registration.
 * @return				MOSQ_ERR_SUCCESS if authentication succeeds or a mosquitto error code describing the failure.
 */
int oauth2plugin_callback_mosquittoBasicAuthentication(
	int event,
	void* event_data,
	void* userdata
);


/**
 * @brief Query the OAuth2 introspection endpoint and store the response.
 *
 * @param introspection_endpoint	URL of the introspection endpoint.
 * @param client_id 				OAuth2 client identifier.
 * @param client_secret				OAuth2 client secret.
 * @param token						Access token supplied by the MQTT client.
 * @param tls_verification			Whether to verify TLS certificates.
 * @param timeout					HTTP request timeout in seconds.
 * @param buffer					Output buffer receiving the response body.
 * @return							MOSQ_ERR_SUCCESS on success, MOSQ_ERR_UNKNOWN otherwise.
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
 * @brief CURL write callback used to collect HTTP response data.
 *
 * @param contents	Pointer to the received data chunk.
 * @param size		Size of one element in bytes.
 * @param nmemb		Number of elements pointed to by @p contents.
 * @param userp		Pointer to an oauth2plugin_CURLBuffer used as destination.
 * @return 			Number of bytes processed. Returning a different value will abort the transfer.
 */
static size_t oauth2plugin_callback_curlWriteFunction(
	void* contents,
	size_t size,
	size_t nmemb,
	void* userp
);


/**
 * @brief Validate a username against a template with optional placeholders.
 *
 * @param username					Actual MQTT username provided by the client.
 * @param template					Template string that the username must match.
 * @param replacement_map			Array of placeholder replacements.
 * @param replacement_map_count		Number of entries in @p replacement_map.
 * @return 							true if the username matches the template, otherwise false.
 */
static bool oauth2plugin_isUsernameValid(
	const char* username,
	const char* template,
	const struct oauth2plugin_strReplacementMap* replacement_map,
	size_t replacement_map_count
);


/**
 * @brief Check whether the token described by the introspection response is active.
 *
 * @param introspection_response	Parsed JSON object returned from the introspection endpoint.
 * @return 							true if the response contains {"active": true}, otherwise false.
 */
static bool oauth2plugin_isTokenActive(
	const cJSON* introspection_response
);


/**
 * @brief Replace the MQTT client's username with a template based value.
 *
 * @param client					Mosquitto client instance to update.
 * @param template					Template used to generate the new username.
 * @param replacement_map			Array with placeholder replacements.
 * @param replacement_map_count		Number of entries in @p replacement_map.
 * @return 							true if the username was successfully set, false otherwise.
 */
static bool oauth2plugin_setUsername(
	struct mosquitto* client,
	const char* template,
	const struct oauth2plugin_strReplacementMap* replacement_map,
	size_t replacement_map_count
);


/**
 * @brief Translate a verification error to the corresponding mosquitto error.
 *
 * @param error		Desired behaviour after a failed verification step.
 * @param client 	Mosquitto client instance used for logging purposes.
 * @return			MOSQ_ERR_AUTH, MOSQ_ERR_PLUGIN_DEFER or other mosquitto error codes based on @p error.
 */
static int oauth2plugin_getMosquittoAuthError(
	enum oauth2plugin_Options_verification_error error,
	const struct mosquitto* client
);

#endif // OAUTH2PLUGIN_AUTH_H