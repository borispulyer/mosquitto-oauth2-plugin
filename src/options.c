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
		// mqtt_username
		else if (
			strcmp(mosquitto_options[i].key, "mqtt_username") == 0 
			&& mosquitto_options[i].value
		) {
			options->mqtt_username = strdup(mosquitto_options[i].value);
			options->verify_username = false;
		}
		// set_username_from_introspection
		else if (
			strcmp(mosquitto_options[i].key, "set_username_from_introspection") == 0
			&& mosquitto_options[i].value
		) {
			if (strcmp(mosquitto_options[i].value, "false") == 0) options->set_username_from_introspection = false;
			else if (strcmp(mosquitto_options[i].value, "true") == 0) options->set_username_from_introspection = true;
		}
		// verify_tls_certificate
		else if (
			strcmp(mosquitto_options[i].key, "verify_tls_certificate") == 0
			&& mosquitto_options[i].value
		) {
			if (strcmp(mosquitto_options[i].value, "false") == 0) options->verify_tls_certificate = false;
			else if (strcmp(mosquitto_options[i].value, "true") == 0) options->verify_tls_certificate = true;
		}
		// verify_username
		else if (
			strcmp(mosquitto_options[i].key, "verify_username") == 0
			&& mosquitto_options[i].value
			&& !options->mqtt_username
		) {
			if (strcmp(mosquitto_options[i].value, "false") == 0) options->verify_username = false;
			else if (strcmp(mosquitto_options[i].value, "true") == 0) options->verify_username = true;
		}
		// timeout
		else if (
			strcmp(mosquitto_options[i].key, "timeout") == 0
		) {
			options->timeout = strtol(mosquitto_options[i].value, NULL, 10);
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
	free(options);
}