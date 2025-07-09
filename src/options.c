/**
 * options.c
 * 
 * Handle plugin_opt_* options from mosquitto.conf file
 */

#include "options.h"


/**
 * Create an Options Object
 */
struct oauth2plugin_Options* oauth2plugin_initOptions() {
	struct oauth2plugin_Options* _options = calloc(1, sizeof(*_options));
	if (!_options) return NULL;
	return _options;
}


/**
 * Apply plugin_opt_* key/value pairs from Mosquitto .conf-file to an existing Options instance.
 */
int oauth2plugin_applyOptions(
	struct oauth2plugin_Options* options,
	const struct mosquitto_opt* mosquitto_options,
	const int mosquitto_options_count
) {
	// Validate
	if (
		!options
		|| !mosquitto_options
		|| mosquitto_options_count < 1
	) return MOSQ_ERR_UNKNOWN;

	// Iterate through mosquitto_options
	for (int i = 0; i < mosquitto_options_count; i++) {
		// introspection_endpoint
		if (
			strcmp(mosquitto_options[i].key, "introspection_endpoint") == 0 
			&& mosquitto_options[i].value
		) {
			options->introspection_endpoint = strdup(mosquitto_options[i].value);
		}
		// tls_verification
		else if (
			strcmp(mosquitto_options[i].key, "tls_verification") == 0
			&& mosquitto_options[i].value
		) {
			if (strcmp(mosquitto_options[i].value, "false") == 0) options->tls_verification = false;
			else if (strcmp(mosquitto_options[i].value, "true") == 0) options->tls_verification = true;
		}
		// timeout
		else if (
			strcmp(mosquitto_options[i].key, "timeout") == 0
		) {
			options->timeout = strtol(mosquitto_options[i].value, NULL, 10);
		}
		// client_id
		else if (
			strcmp(mosquitto_options[i].key, "client_id") == 0 
			&& mosquitto_options[i].value
		) {
			options->client_id = strdup(mosquitto_options[i].value);
		}
		// client_secret
		else if (
			strcmp(mosquitto_options[i].key, "client_secret") == 0 
			&& mosquitto_options[i].value
		) {
			options->client_secret = strdup(mosquitto_options[i].value);
		}
		// username_validation
		else if (
			strcmp(mosquitto_options[i].key, "username_validation") == 0 
			&& mosquitto_options[i].value
		) {
			if (strcmp(mosquitto_options[i].value, "none") == 0 ) options->username_validation = NONE;
			else if (strcmp(mosquitto_options[i].value, "oidc-username") == 0 ) options->username_validation = OIDC_USERNAME;
			else if (strcmp(mosquitto_options[i].value, "oidc-email") == 0 ) options->username_validation = OIDC_EMAIL;
			else if (strcmp(mosquitto_options[i].value, "oidc-sub") == 0 ) options->username_validation = OIDC_SUB;
			else if (strcmp(mosquitto_options[i].value, "template") == 0 ) options->username_validation = TEMPLATE;
		}
		// username_validation_template
		else if (
			strcmp(mosquitto_options[i].key, "username_validation_template") == 0 
			&& mosquitto_options[i].value
		) {
			options->username_validation_template = strdup(mosquitto_options[i].value);
		}
		// username_validation_error
		else if (
			strcmp(mosquitto_options[i].key, "username_validation_error") == 0 
			&& mosquitto_options[i].value
		) {
			if (strcmp(mosquitto_options[i].value, "deny") == 0 ) options->username_validation_error = DENY;
			else if (strcmp(mosquitto_options[i].value, "defer") == 0 ) options->username_validation_error = DEFER;
		}
		// username_replacement
		else if (
			strcmp(mosquitto_options[i].key, "username_replacement") == 0 
			&& mosquitto_options[i].value
		) {
			if (strcmp(mosquitto_options[i].value, "none") == 0 ) options->username_replacement = NONE;
			else if (strcmp(mosquitto_options[i].value, "oidc-username") == 0 ) options->username_replacement = OIDC_USERNAME;
			else if (strcmp(mosquitto_options[i].value, "oidc-email") == 0 ) options->username_replacement = OIDC_EMAIL;
			else if (strcmp(mosquitto_options[i].value, "oidc-sub") == 0 ) options->username_replacement = OIDC_SUB;
			else if (strcmp(mosquitto_options[i].value, "template") == 0 ) options->username_replacement = TEMPLATE;
		}
		// username_replacement_template
		else if (
			strcmp(mosquitto_options[i].key, "username_replacement_template") == 0 
			&& mosquitto_options[i].value
		) {
			options->username_replacement_template = strdup(mosquitto_options[i].value);
		}
		// username_replacement_error
		else if (
			strcmp(mosquitto_options[i].key, "username_replacement_error") == 0 
			&& mosquitto_options[i].value
		) {
			if (strcmp(mosquitto_options[i].value, "deny") == 0 ) options->username_replacement_error = DENY;
			else if (strcmp(mosquitto_options[i].value, "defer") == 0 ) options->username_replacement_error = DEFER;
		}
		// token_verification_error
		else if (
			strcmp(mosquitto_options[i].key, "token_verification_error") == 0 
			&& mosquitto_options[i].value
		) {
			if (strcmp(mosquitto_options[i].value, "deny") == 0 ) options->token_verification_error = DENY;
			else if (strcmp(mosquitto_options[i].value, "defer") == 0 ) options->token_verification_error = DEFER;
		}
	}

	// Check for mandatory options
	if(
		!options->introspection_endpoint 
		|| !options->client_id 
		|| !options->client_secret
	) return MOSQ_ERR_INVAL;

	// Return
	return MOSQ_ERR_SUCCESS;
}


/**
 * Free Options Object
 */
void oauth2plugin_freeOptions(
	struct oauth2plugin_Options *options
) {
	if(!options) return;
	free(options->introspection_endpoint);
	free(options->client_id);
	free(options->client_secret);
	free(options->username_validation_template);
	free(options->username_replacement_template);
	free(options);
}


/**
 * Convert enum oauth2plugin_Options_username_validation to string for logging
 */
const char* oauth2plugin_Options_username_validation_toString(
	enum oauth2plugin_Options_username_validation value
) {
	switch (value) {
		case NONE: return "none";
		case OIDC_USERNAME: return "oidc_username";
		case OIDC_EMAIL: return "oidc_email";
		case OIDC_SUB: return "oidc_sub";
		case TEMPLATE: return "template";
		default: return "unknown";
	}
}


/**
 * Convert enum oauth2plugin_Options_username_replacement to string for logging
 */
const char* oauth2plugin_Options_username_replacement_toString(
	enum oauth2plugin_Options_username_replacement value
) {
	switch (value) {
		case NONE: return "none";
		case OIDC_USERNAME: return "oidc_username";
		case OIDC_EMAIL: return "oidc_email";
		case OIDC_SUB: return "oidc_sub";
		case TEMPLATE: return "template";
		default: return "unknown";
	}
}


/**
 * Convert enum oauth2plugin_Options_verification_error to string for logging
 */

const char* oauth2plugin_Options_verification_error_toString(
	enum oauth2plugin_Options_verification_error value
) {
	switch (value) {
		case DENY: return "deny";
		case DEFER: return "defer";
		default: return "unknown";
	}
}