/**
 * options.h
 * 
 * Handle plugin_opt_* options from mosquitto.conf file
 */

#ifndef OAUTH2PLUGIN_OPTIONS_H
#define OAUTH2PLUGIN_OPTIONS_H

#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <mosquitto.h>
#include <mosquitto_broker.h>
#include <mosquitto_plugin.h>


/**
 * Options structure holding all plugin_opt_* values after parsing mosquitto.conf.
 * Pointer members are heap‑allocated and must be released via oauth2plugin_freeOptions().
 */
struct oauth2plugin_Options {
	mosquitto_plugin_id_t* id;				// Plugin ID from MQTT Broker.
	char* introspection_endpoint;			// Introspection Endpoint URL.
	char* client_id;						// OAuth2 Client ID.
	char* client_secret;					// OAuth2 Client Secret.
	char* mqtt_username;					// If set, plugin will only handle authentication, if the username from the MQTT client matches. Otherwise it will send MOSQ_ERR_PLUGIN_DEFER. Disables the verify_username option. 
	bool set_username_from_introspection;	// Use the 'username' field from the introspection response.
	bool verify_username;					// MQTT client username must match the OAuth2 username from the introspection endpoint. 
	bool verify_tls_certificate;			// Disable TLS verification for testing.
	long timeout;							// Timeout in seconds.
};

/**
 * Create an Options Object.
 */
struct oauth2plugin_Options* oauth2plugin_initOptions();


/**
 * Apply plugin_opt_* key/value pairs from Mosquitto .conf-file to an existing Options instance.
 */
int oauth2plugin_applyOptions(
	struct oauth2plugin_Options* options,
	const struct mosquitto_opt* mosquitto_options,
	const int mosquitto_options_count
);


/**
 * Free all heap allocations inside struct Options and the object itself.
 */
void oauth2plugin_freeOptions(
	struct oauth2plugin_Options *options
);

#endif // OAUTH2PLUGIN_OPTIONS_H