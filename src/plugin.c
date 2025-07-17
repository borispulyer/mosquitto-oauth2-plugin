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
 * Required packages:
 *   – libmosquitto-dev / mosquitto-dev (broker headers & API)
 *   – libcurl4-openssl-dev (HTTP requests)
 *   - cjson-dev (JSON parsing)
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
 * @brief Initialize the Mosquitto OAuth2 plugin.
 *
 * This function is called by the broker when the plugin is loaded.
 * It parses the configuration options, registers the authentication 
 * callback and initializes the CURL library used for HTTP requests.
 *
 * @param identifier	Plugin identifier provided by Mosquitto.
 * @param userdata		Pointer that will receive plugin specific data and is passed back to mosquitto_plugin_cleanup().
 * @param options 		Array with key/value pairs from the configuration.
 * @param option_count	Number of entries in the options array.
 * @return 				MOSQ_ERR_SUCCESS on success or a suitable Mosquitto error code on failure.
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
		mosquitto_log_printf(MOSQ_LOG_ERR, "[OAuth2 Plugin][E] Failed to initialize Plugin: Initialization of CURL failed.");
		return MOSQ_ERR_UNKNOWN;
	}

	// Handle plugin_opt_* options from mosquitto.conf file
	struct oauth2plugin_Options* _options = oauth2plugin_initOptions();
	if (!_options) return MOSQ_ERR_NOMEM;
	
	// Set default options
	_options->id = identifier;
	_options->tls_verification = true;
	_options->timeout = 5;
	_options->username_validation = false;
	_options->username_validation_error = verification_error_DEFER;
	_options->username_replacement = false;
	_options->username_replacement_error = verification_error_DENY;
	_options->token_verification_error = verification_error_DENY;

	// Apply options from mosquitto.conf	
	int apply_options_error = oauth2plugin_applyOptions(_options, options, option_count);
	if (apply_options_error) {
		if (apply_options_error == MOSQ_ERR_INVAL) 
			mosquitto_log_printf(MOSQ_LOG_ERR, "[OAuth2 Plugin][E] Failed to initialize Plugin: Options 'plugin_opt_introspection_endpoint', 'plugin_opt_client_id' and 'plugin_opt_client_secret' are mandatory.");
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

	// Log
	mosquitto_log_printf(MOSQ_LOG_INFO,  "[OAuth2 Plugin][I] Plugin successfully initialized.");
	mosquitto_log_printf(MOSQ_LOG_INFO,  "[OAuth2 Plugin][I]  - Introspection Endpoint: %s", _options->introspection_endpoint);
	mosquitto_log_printf(MOSQ_LOG_DEBUG, "[OAuth2 Plugin][D]  - TLS Verification: %s", _options->tls_verification ? "<Enabled>" : "<Disabled>");
	mosquitto_log_printf(MOSQ_LOG_DEBUG, "[OAuth2 Plugin][D]  - Timeout: %ld seconds", _options->timeout);
	mosquitto_log_printf(MOSQ_LOG_DEBUG, "[OAuth2 Plugin][D]  - OAuth2 Client ID: %s", _options->client_id);
	mosquitto_log_printf(MOSQ_LOG_DEBUG, "[OAuth2 Plugin][D]  - OAuth2 Client Secret: %zu chars", strlen(_options->client_secret));
	mosquitto_log_printf(MOSQ_LOG_DEBUG, "[OAuth2 Plugin][D]  - Username Verification: %s", _options->username_validation ? "<Enabled>" : "<Disabled>");
	mosquitto_log_printf(MOSQ_LOG_DEBUG, "[OAuth2 Plugin][D]  - Username Verification Template: %s", _options->username_validation_template ? _options->username_validation_template : "<None>");
	mosquitto_log_printf(MOSQ_LOG_DEBUG, "[OAuth2 Plugin][D]  - Username Verification Error: <%s>", oauth2plugin_Options_verification_error_toString(_options->username_validation_error));
	mosquitto_log_printf(MOSQ_LOG_DEBUG, "[OAuth2 Plugin][D]  - Username Replacement: %s", _options->username_replacement ? "<Enabled>" : "<Disabled>");
	mosquitto_log_printf(MOSQ_LOG_DEBUG, "[OAuth2 Plugin][D]  - Username Replacement Template: %s", _options->username_replacement_template ? _options->username_replacement_template : "<None>");
	mosquitto_log_printf(MOSQ_LOG_DEBUG, "[OAuth2 Plugin][D]  - Username Replacement Error: <%s>", oauth2plugin_Options_verification_error_toString(_options->username_replacement_error));
	mosquitto_log_printf(MOSQ_LOG_DEBUG, "[OAuth2 Plugin][D]  - Token Verification Error: <%s>", oauth2plugin_Options_verification_error_toString(_options->token_verification_error));
	
	// Return
	*userdata = _options; // Returned to Mosquitto for mosquitto_plugin_cleanup
	return MOSQ_ERR_SUCCESS;
}


/**
 * @brief Report the plugin API version supported by this plugin.
 *
 * Mosquitto asks the plugin to report which API versions it supports.
 * This implementation only supports API version 5.
 *
 * @param supported_version_count	Number of entries in @p supported_versions.
 * @param supported_versions		Array of API versions supported by the broker.
 * @return							5 if version 5 is supported, otherwise -1 to indicate incompatibility.
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
 * @brief Cleanup function called when the plugin is unloaded.
 *
 * Releases resources created during mosquitto_plugin_init() such as the
 * CURL library state and the options structure.
 *
 * @param userdata		Pointer to plugin specific data returned from mosquitto_plugin_init().
 * @param options		Unused parameter from the broker.
 * @param option_count	Unused parameter from the broker.
 * @return				MOSQ_ERR_SUCCESS on success.
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
