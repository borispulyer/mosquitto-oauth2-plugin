/**
 * options.c
 * 
 * Handle plugin_opt_* options from mosquitto.conf file
 */

#include "options.h"


const struct oauth2plugin_oidc_placeholder oauth2plugin_oidc_template_placeholders[] = {
	{"%%oidc-username%%", "username"},
	{"%%oidc-email%%", "email"},
	{"%%oidc-sub%%", "sub"}
};
const size_t oauth2plugin_oidc_template_placeholders_count =
	sizeof(oauth2plugin_oidc_template_placeholders) /
	sizeof(oauth2plugin_oidc_template_placeholders[0]);


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
			if (strcmp(mosquitto_options[i].value, "false") == 0) options->username_validation = false;
			else if (strcmp(mosquitto_options[i].value, "true") == 0) options->username_validation = true;
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
			if (strcmp(mosquitto_options[i].value, "deny") == 0 ) options->username_validation_error = verification_error_DENY;
			else if (strcmp(mosquitto_options[i].value, "defer") == 0 ) options->username_validation_error = verification_error_DEFER;
		}
		// username_replacement
		else if (
			strcmp(mosquitto_options[i].key, "username_replacement") == 0
			&& mosquitto_options[i].value
		) {
			if (strcmp(mosquitto_options[i].value, "false") == 0) options->username_replacement = false;
			else if (strcmp(mosquitto_options[i].value, "true") == 0) options->username_replacement = true;
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
			if (strcmp(mosquitto_options[i].value, "deny") == 0 ) options->username_replacement_error = verification_error_DENY;
			else if (strcmp(mosquitto_options[i].value, "defer") == 0 ) options->username_replacement_error = verification_error_DEFER;
		}
		// token_verification_error
		else if (
			strcmp(mosquitto_options[i].key, "token_verification_error") == 0 
			&& mosquitto_options[i].value
		) {
			if (strcmp(mosquitto_options[i].value, "deny") == 0 ) options->token_verification_error = verification_error_DENY;
			else if (strcmp(mosquitto_options[i].value, "defer") == 0 ) options->token_verification_error = verification_error_DEFER;
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
 * Convert enum oauth2plugin_Options_verification_error to string for logging
 */

const char* oauth2plugin_Options_verification_error_toString(
	enum oauth2plugin_Options_verification_error value
) {
	switch (value) {
		case verification_error_DENY: return "deny";
		case verification_error_DEFER: return "defer";
		default: return "unknown";
	}
}