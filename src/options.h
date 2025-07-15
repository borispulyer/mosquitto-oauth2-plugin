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


enum oauth2plugin_Options_verification_error {
	verification_error_DENY,
	verification_error_DEFER
}; 

/**
 * Options structure holding all plugin_opt_* values after parsing mosquitto.conf.
 * Pointer members are heap‑allocated and must be released via oauth2plugin_freeOptions().
 */
struct oauth2plugin_Options {	
	mosquitto_plugin_id_t* 							id;										// Plugin ID from MQTT Broker.
	char* 											introspection_endpoint;					// Introspection Endpoint URL.
	char* 											client_id;								// OAuth2 Client ID.
	char* 											client_secret;							// OAuth2 Client Secret.
	bool 											tls_verification;						// Enable TLS verification.
	long 											timeout;								// Server timeout in seconds.
 	bool											username_validation;					// Validate username to match username_validation_template
	char* 											username_validation_template;			// "token-%oidc-username%"
 	enum oauth2plugin_Options_verification_error	username_validation_error;				// "defer", "deny"
 	bool										 	username_replacement;					// Replace username after successful authentification
 	char* 											username_replacement_template;			// "%username%-%rolescope%"
 	enum oauth2plugin_Options_verification_error 	username_replacement_error;				// "defer", "deny"
 	enum oauth2plugin_Options_verification_error 	token_verification_error;				// "defer", "deny"
};


struct { 
	const char* placeholder; 
	const char* oidc_key; 
} oauth2plugin_oidc_template_placeholders[] = {
	{"%%oidc-username%%", "username"},
	{"%%oidc-email%%", "email"},
	{"%%oidc-sub%%", "sub"}
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

const char* oauth2plugin_Options_verification_error_toString(
	enum oauth2plugin_Options_verification_error value
);

#endif // OAUTH2PLUGIN_OPTIONS_H