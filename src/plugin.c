/*
 * Mosquitto OAuth2 Plugin
 *
 * Lightweight authentication plugin for the Eclipse Mosquitto broker
 * (Plugin API version 5).
 *
 * How it works:
 *   – Reads the MQTT *password* field from the CONNECT packet
 *   – Sends the token to an external HTTP authentication server.
 *   – Grants or denies the connection depending on the HTTP response code.
 *
 * mosquitto.conf configuration (example):
 *   plugin /etc/mosquitto/plugins/mosquitto_token_auth_plugin.so
 *   plugin_opt_url https://auth.example.com/validate
 *   plugin_opt_timeout 3          # curl timeout in seconds (optional)
 *
 * Required packages:
 *   – libmosquitto-dev / mosquitto-dev (broker headers & API)
 *   – libcurl4-openssl-dev (HTTP requests)
 */


#include <stdbool.h>

#include <mosquitto.h>
#include <mosquitto_broker.h>
#include <mosquitto_plugin.h>
#include <curl/curl.h>
#include "cJSON.h"

#include "options.h"
#include "auth.h"


/**
 * Initialize Mosquitto OAuth2 Plugin
 */
int mosquitto_plugin_init(
	mosquitto_plugin_id_t* identifier, 
	void** userdata, 
	struct mosquitto_opt* options, 
	int option_count
) {
	
	// Log
	mosquitto_log_printf(MOSQ_LOG_DEBUG, "[OAuth2 Plugin][D] Initializing Plugin...");
	
	// Validation
	if(!identifier) return MOSQ_ERR_INVAL;

	// Initialize CURL
	CURLcode curl_global_init_error = curl_global_init(CURL_GLOBAL_DEFAULT);
	if (curl_global_init_error) {
		mosquitto_log_printf(MOSQ_LOG_ERR, "[OAuth2 Plugin][E] Failed to initialize Plugin: Initializiation of CURL failed.");
		return MOSQ_ERR_UNKNOWN;
	}

	// Handle plugin_opt_* options from mosquitto.conf file
	struct oauth2plugin_Options* _options = oauth2plugin_initOptions();
	if (!_options) return MOSQ_ERR_NOMEM;
	
	// Set default options
	_options->id = identifier;
	_options->tls_verification = true;
	_options->timeout = 5;
	_options->username_verification = NONE;
	_options->username_verification_error = DENY;
	_options->username_replacement = NONE;
	_options->token_verification_error = DENY;

	// Apply options from mosquitto.conf	
	int apply_options_error = oauth2plugin_applyOptions(_options, options, option_count);
	if (apply_options_error) {
		if (apply_options_error == MOSQ_ERR_INVAL) 
			mosquitto_log_printf(MOSQ_LOG_ERR, "[OAuth2 Plugin][E] Failed to initialize Plugin: Options 'introspection_endpoint', 'client_id' and 'client_secret' are mandatory.");
		else
			mosquitto_log_printf(MOSQ_LOG_ERR, "[OAuth2 Plugin][E] Failed to initialize Plugin.");
		oauth2plugin_freeOptions(_options);
		return apply_options_error;
	}

	// Register Callbacks
	int register_callback_error = mosquitto_callback_register(identifier, MOSQ_EVT_BASIC_AUTH, oauth2plugin_callback_mosquittoBasicAuthentication, NULL, _options);
	if (register_callback_error != MOSQ_ERR_SUCCESS) {
		mosquitto_log_printf(MOSQ_LOG_ERR, "[OAuth2 Plugin][E] Failed to initialize Plugin: Cannot register authentication callback function (Error: %s).", mosquitto_strerror(register_callback_error));
		oauth2plugin_freeOptions(_options);
		return register_callback_error;
	}

	// Finish
	*userdata = _options; // Return to Mosquitto for mosquitto_plugin_cleanup
	mosquitto_log_printf(MOSQ_LOG_INFO,  "[OAuth2 Plugin][I] Plugin successfully initialized.");
	mosquitto_log_printf(MOSQ_LOG_INFO,  "[OAuth2 Plugin][I]  - Introspection Endpoint: %s", _options->introspection_endpoint);
	mosquitto_log_printf(MOSQ_LOG_DEBUG, "[OAuth2 Plugin][D]  - OAuth2 Client ID: %s", _options->client_id);
	mosquitto_log_printf(MOSQ_LOG_DEBUG, "[OAuth2 Plugin][D]  - OAuth2 Client Secret: %zu chars",strlen(_options->client_secret));
	mosquitto_log_printf(MOSQ_LOG_DEBUG, "[OAuth2 Plugin][D]  - MQTT Username: %s", _options->mqtt_username ? _options->mqtt_username : "<None>");
	mosquitto_log_printf(MOSQ_LOG_DEBUG, "[OAuth2 Plugin][D]  - Set MQTT Username to OAuth2 Username: %s", _options->set_username_from_introspection ? "<Enabled>" : "<Disabled>");
	mosquitto_log_printf(MOSQ_LOG_DEBUG, "[OAuth2 Plugin][D]  - Verify TLS: %s", _options->verify_tls_certificate ? "<Enabled>" : "<Disabled>");
	mosquitto_log_printf(MOSQ_LOG_DEBUG, "[OAuth2 Plugin][D]  - Verify Username: %s", _options->verify_username ? "<Enabled>" : "<Disabled>");
	mosquitto_log_printf(MOSQ_LOG_DEBUG, "[OAuth2 Plugin][D]  - Timeout: %ld seconds", _options->timeout);
	return MOSQ_ERR_SUCCESS;
}


/**
 * Returns the Plugin API version. Only v5 is supported.
 */
int mosquitto_plugin_version(
	int supported_version_count, 
	const int* supported_versions
) {	
	// Only Version 5 is supported
	for (int i = 0; i < supported_version_count; i++) {
		if (supported_versions[i] == 5) return 5;
	}

	// Incompatible
	return -1; 
}


/**
 * Cleanup.
 */
int mosquitto_plugin_cleanup(
	void* userdata, 
	struct mosquitto_opt* options, 
	int option_count
) {	
	// Unused Parameters
	(void)options; (void)option_count;

	// Clean Options
	if (userdata) {
		struct oauth2plugin_Options* _options = (struct oauth2plugin_Options*) userdata;
		mosquitto_callback_unregister(_options->id, MOSQ_EVT_BASIC_AUTH, oauth2plugin_callback_mosquittoBasicAuthentication, _options);
		oauth2plugin_freeOptions(_options);
	}

	// Clean CURL
	curl_global_cleanup();

	// Log
	mosquitto_log_printf(MOSQ_LOG_DEBUG, "[OAuth2 Plugin][D] Cleanup successful.");

	// Return
	return MOSQ_ERR_SUCCESS;
}