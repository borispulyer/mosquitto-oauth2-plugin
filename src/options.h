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


struct oauth2plugin_template_placeholder {
	const char* placeholder;
	const char* oidc_key;
};
extern const struct oauth2plugin_template_placeholder oauth2plugin_template_placeholders[];
extern const size_t oauth2plugin_oidc_template_placeholders_count;


/**
 * @brief Allocate and initialize an options structure.
 *
 * All fields of the returned structure are set to zero. The caller is
 * responsible for releasing the object with oauth2plugin_freeOptions().
 *
 * @return Pointer to a new options structure or NULL if allocation fails.
 */
struct oauth2plugin_Options* oauth2plugin_initOptions();


/**
 * @brief Apply plugin configuration options to an options structure.
 *
 * The key/value pairs supplied by the broker are parsed and copied into
 * the given options structure.
 *
 * @param options					Target options object to fill.
 * @param mosquitto_options			Array of options supplied by the broker.
 * @param mosquitto_options_count	Number of entries in @p mosquitto_options.
 * @return							MOSQ_ERR_SUCCESS on success, MOSQ_ERR_INVAL if mandatory options are missing or MOSQ_ERR_UNKNOWN on other failures.
 */
int oauth2plugin_applyOptions(
	struct oauth2plugin_Options* options,
	const struct mosquitto_opt* mosquitto_options,
	const int mosquitto_options_count
);


/**
 * @brief Release all allocations inside an options object.
 *
 * Frees any memory referenced by the options structure and finally the structure itself.
 *
 * @param options 					Pointer to the options object created by oauth2plugin_initOptions(). May be NULL.
 */
void oauth2plugin_freeOptions(
	struct oauth2plugin_Options* options
);


/**
 * @brief Convert a verification_error enum value to a human readable string.
 *
 * Primarily used for log output.
 *
 * @param value						Enumeration value to convert.
 * @return							Constant string representation of @p value.
 */
const char* oauth2plugin_Options_verification_error_toString(
	enum oauth2plugin_Options_verification_error value
);

#endif // OAUTH2PLUGIN_OPTIONS_H