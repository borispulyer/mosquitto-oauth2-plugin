/**
 * auth.c
 * 
 * Handle OAuth2 authentication
 */

#include "auth.h"


static int oauth2plugin_getMosquittoAuthError(
	enum oauth2plugin_Options_verification_error error,
	const struct mosquitto* client
) {
	const char* mqtt_client_id = mosquitto_client_id(client);
	switch (error) {
		case verification_error_DENY:
			mosquitto_log_printf(MOSQ_LOG_INFO, "[OAuth2 Plugin][I] Authentication failed. ACCESS DENIED (MQTT Client ID: %s).", mqtt_client_id);
			return MOSQ_ERR_AUTH; // Access denied
			break;
		case verification_error_DEFER:
			mosquitto_log_printf(MOSQ_LOG_INFO, "[OAuth2 Plugin][I] Authentication failed. DEFERRING AUTHENTICATION (MQTT Client ID: %s).", mqtt_client_id);
			return MOSQ_ERR_PLUGIN_DEFER; // Deferring authentication
			break;
	}
	return MOSQ_ERR_AUTH; // Access denied
}


static bool oauth2plugin_isUsernameValid(
	const char* username,
	const char* template,
	const struct oauth2plugin_strReplacementMap* replacement_map,
	size_t replacement_map_count
) {

	// Validation
	if (!username || !template) return false;
	
	// Empty username cannot be not validated
	if (strlen(username) == 0) {
		mosquitto_log_printf(MOSQ_LOG_DEBUG, "[OAuth2 Plugin][D] MQTT client sent empty username.");
		mosquitto_log_printf(MOSQ_LOG_DEBUG, "[OAuth2 Plugin][D]  - MQTT client username: %s", username ? username : "<none>");
		mosquitto_log_printf(MOSQ_LOG_DEBUG, "[OAuth2 Plugin][D]  - Username verification template: %s", template);
		return false;
	}
	
	// Replace placeholders in template
	char* username_comparison = NULL;
	if (strstr(template, "%%") != NULL) {
		// Username template contains placeholders -> replace
		if (!replacement_map
			|| replacement_map_count == 0) return true;
		username_comparison = oauth2plugin_strReplaceMap(
			template,
			replacement_map,
			replacement_map_count
		);
		if (username_comparison == NULL) return false;
	} else {
		// Username template does not contain any placeholders
		username_comparison = strdup(template);
	}
	
	// Compare username with template
	if (strcmp(username, username_comparison) == 0) {
		free(username_comparison);
		return true;
	} else {
		mosquitto_log_printf(MOSQ_LOG_DEBUG, "[OAuth2 Plugin][D] Username from MQTT client does not match username template in config file.");
		mosquitto_log_printf(MOSQ_LOG_DEBUG, "[OAuth2 Plugin][D]  - MQTT client username: %s", username ? username : "<none>");
		mosquitto_log_printf(MOSQ_LOG_DEBUG, "[OAuth2 Plugin][D]  - Username verification template: %s", template);
		mosquitto_log_printf(MOSQ_LOG_DEBUG, "[OAuth2 Plugin][D]  - Username comparison string: %s", username_comparison);
		free(username_comparison);
		return false;
	}
	
	free(username_comparison);
	return false;
}


static bool oauth2plugin_isTokenActive(
	const cJSON* introspection_response
) {
	// Validate
	if (!introspection_response) return false;

	// Check for {"active": true}
	cJSON* cjson_active = cJSON_GetObjectItemCaseSensitive(introspection_response, "active");
	if (
		cJSON_IsBool(cjson_active) 
		&& cJSON_IsTrue(cjson_active)
	) return true;
	
	// Otherwise return false
	mosquitto_log_printf(MOSQ_LOG_DEBUG, "[OAuth2 Plugin][D] Introspection response is not {\"active\": true}. Token is not active.");
	return false;
}


static bool oauth2plugin_setUsername(
	struct mosquitto* client,
	const char* template,
	const struct oauth2plugin_strReplacementMap* replacement_map,
	size_t replacement_map_count
) {
	// Validation
	if (!client || !template) return false;
	
	// Replace placeholders in template
	char* username = NULL;
	if (strstr(template, "%%") != NULL) {
		// Username template contains placeholders -> replace
		if (!replacement_map
			|| replacement_map_count == 0) return false;
		username = oauth2plugin_strReplaceMap(
			template,
			replacement_map,
			replacement_map_count
		);
		if (username == NULL) return false;
	} else {
		// Username template does not contain any placeholders
		username = strdup(template);
	}

	// Replace username
	if (username) {
		mosquitto_log_printf(MOSQ_LOG_DEBUG, "[OAuth2 Plugin][D] Replacing username with template from config file.");
		mosquitto_log_printf(MOSQ_LOG_DEBUG, "[OAuth2 Plugin][D]  - Username replacement template: %s", template ? template : "<none>");
		mosquitto_log_printf(MOSQ_LOG_DEBUG, "[OAuth2 Plugin][D]  - New username: %s", username ? username : "<none>");
		mosquitto_set_username(client, username);
		free(username);
		return true;
	}

	free(username);
	return false;

}


static size_t oauth2plugin_callback_curlWriteFunction(
	void* contents, 
	size_t size, 
	size_t nmemb, 
	void* userp
) {
	size_t contents_size = size * nmemb;
	struct oauth2plugin_CURLBuffer* buffer = (struct oauth2plugin_CURLBuffer*) userp;

	char* data = realloc(buffer->data, buffer->size + contents_size + 1);
	if (!data) return 0;

	buffer->data = data;

	memcpy(&(buffer->data[buffer->size]), contents, contents_size);

	buffer->size += contents_size;
	buffer->data[buffer->size] = '\0';
	
	return contents_size;
}


static int oauth2plugin_callIntrospectionEndpoint(
	const char* introspection_endpoint,
	const char* client_id,
	const char* client_secret,
	const char* token,
	const bool tls_verification,
	const long timeout,
	struct oauth2plugin_CURLBuffer* buffer
) {
	// Validation
	if (
		!client_id
		|| !client_secret
		|| !token
	) return MOSQ_ERR_UNKNOWN;

	// Init CURL
	CURL* curl = curl_easy_init();
	if (!curl) return MOSQ_ERR_UNKNOWN;

	// Escape client_id and client_secret
	char* esc_client_id = curl_easy_escape(curl, client_id, 0);
	char* esc_client_secret = curl_easy_escape(curl, client_secret, 0);
	if (!esc_client_id
		|| !esc_client_secret) {
		curl_easy_cleanup(curl);
		return MOSQ_ERR_UNKNOWN;
	}

	// Create POST data for token
	char* postadata_token_parameter = "token";
	char* postdata_token_value = curl_easy_escape(curl, token, 0);
	if (!postdata_token_value) {
		curl_easy_cleanup(curl);
		return MOSQ_ERR_UNKNOWN;
	}
	char* postdata_token = (char*) malloc(strlen(postadata_token_parameter) + strlen(postdata_token_value) + 2); // +1 for '=' and +1 for null terminator
	if (!postdata_token) {
		curl_free(postdata_token_value);
		curl_easy_cleanup(curl);
		return MOSQ_ERR_NOMEM;
	}
	sprintf(postdata_token, "%s=%s", postadata_token_parameter, postdata_token_value);
	curl_free(postdata_token_value);
	
	// Setup CURL
	curl_easy_setopt(curl, CURLOPT_URL, introspection_endpoint);
	curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
	curl_easy_setopt(curl, CURLOPT_USERNAME, esc_client_id);
	curl_easy_setopt(curl, CURLOPT_PASSWORD, esc_client_secret);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postdata_token);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, oauth2plugin_callback_curlWriteFunction);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, buffer);
	if (!tls_verification) {
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
	}
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout);

	// Log
	mosquitto_log_printf(MOSQ_LOG_DEBUG, "[OAuth2 Plugin][D] Performing introspection endpoint request...");
	mosquitto_log_printf(MOSQ_LOG_DEBUG, "[OAuth2 Plugin][D]  - URL: %s", introspection_endpoint);
	mosquitto_log_printf(MOSQ_LOG_DEBUG, "[OAuth2 Plugin][D]  - OAuth2 Client ID: %s", client_id);
	mosquitto_log_printf(MOSQ_LOG_DEBUG, "[OAuth2 Plugin][D]  - OAuth2 Client Secret: %zu chars", strlen(client_secret));
	mosquitto_log_printf(MOSQ_LOG_DEBUG, "[OAuth2 Plugin][D]  - POST Data: %s", postdata_token);
	mosquitto_log_printf(MOSQ_LOG_DEBUG, "[OAuth2 Plugin][D]  - TLS: %s", tls_verification ? "<Enabled>" : "<Disabled>");
	mosquitto_log_printf(MOSQ_LOG_DEBUG, "[OAuth2 Plugin][D]  - Timeout: %ld", timeout);
	
	// Perform HTTP request
	CURLcode curl_code = curl_easy_perform(curl);
	curl_free(esc_client_id);
	curl_free(esc_client_secret);
	free(postdata_token);
	if (curl_code != CURLE_OK) {
		mosquitto_log_printf(MOSQ_LOG_WARNING, "[OAuth2 Plugin][W] Failed to call introspection endpoint (Error: %s).", curl_easy_strerror(curl_code));
		curl_easy_cleanup(curl);
		return MOSQ_ERR_UNKNOWN;
	}

	// Get Status Code
	long http_code = 0;
	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
	curl_easy_cleanup(curl);

	// Log
	mosquitto_log_printf(MOSQ_LOG_DEBUG, "[OAuth2 Plugin][D] Received response from introspection endpoint.");
	mosquitto_log_printf(MOSQ_LOG_DEBUG, "[OAuth2 Plugin][D]  - HTTP Code: %ld", http_code);
	mosquitto_log_printf(MOSQ_LOG_DEBUG, "[OAuth2 Plugin][D]  - Data: %s", buffer->data);

	// Validate HTTP status code
	if (http_code != 200) {
		mosquitto_log_printf(MOSQ_LOG_WARNING, "[OAuth2 Plugin][W] Failed to call introspection endpoint (HTTP Code: %ld).", http_code);
		return MOSQ_ERR_UNKNOWN;
	}

	// Return
	return MOSQ_ERR_SUCCESS;
}


int oauth2plugin_callback_mosquittoBasicAuthentication(
	int event, 
	void* event_data, 
	void* userdata
) {
	// Unused Parameters
	(void) event;
	
	// Init
	struct mosquitto_evt_basic_auth* data = (struct mosquitto_evt_basic_auth*) event_data;
	struct oauth2plugin_Options* _options = (struct oauth2plugin_Options*) userdata;
	struct oauth2plugin_CURLBuffer buffer = { .data = NULL, .size = 0 };
	const char* mqtt_client_id = mosquitto_client_id(data->client);
	const char* mqtt_username  = mosquitto_client_username(data->client);
	const char* mqtt_password = data->password;

	// Log
	mosquitto_log_printf(MOSQ_LOG_DEBUG, "[OAuth2 Plugin][D] Starting client authentication.");
	mosquitto_log_printf(MOSQ_LOG_DEBUG, "[OAuth2 Plugin][D]  - MQTT Client ID: %s", mqtt_client_id);
	mosquitto_log_printf(MOSQ_LOG_DEBUG, "[OAuth2 Plugin][D]  - MQTT Client Username: %s", mqtt_username ? mqtt_username : "<none>");
	mosquitto_log_printf(MOSQ_LOG_DEBUG, "[OAuth2 Plugin][D]  - MQTT Client Password: %s", mqtt_password ? mqtt_password : "<none>");

	////
	// Step 1: Pre OAuth2 validation
	////

	// Validate username
	if (
		_options->username_validation
		&& !oauth2plugin_isUsernameValid(
			mqtt_username,
			_options->username_validation_template,
			NULL,
			0
		)
	) {
		mosquitto_log_printf(MOSQ_LOG_INFO, "[OAuth2 Plugin][I] Username from MQTT client is not valid (MQTT Client ID: %s).", mqtt_client_id);
		return oauth2plugin_getMosquittoAuthError(_options->username_validation_error, data->client);
	}
	
	// Validate empty password field
	if (mqtt_password == NULL) {
		mosquitto_log_printf(MOSQ_LOG_WARNING, "[OAuth2 Plugin][W] Empty password field -> No token to validate (MQTT Client ID: %s).", mqtt_client_id);
		return oauth2plugin_getMosquittoAuthError(_options->token_verification_error, data->client);
	}

	////
	// Step 2: Perform OAuth2 request
	////

	// Call introspection endpoint
	int error = oauth2plugin_callIntrospectionEndpoint(
		_options->introspection_endpoint,
		_options->client_id,
		_options->client_secret,
		mqtt_password,
		_options->tls_verification,
		_options->timeout,
		&buffer
	);

	// Check for error or empty response data
	if (
		error
		|| !buffer.data
	) {
		mosquitto_log_printf(MOSQ_LOG_WARNING, "[OAuth2 Plugin][W] Failed to validate token (MQTT Client ID: %s).", mqtt_client_id);
		free(buffer.data);
		return oauth2plugin_getMosquittoAuthError(_options->token_verification_error, data->client);
	}

	// Parse JSON
	cJSON* cjson = cJSON_Parse(buffer.data);
	if (!cjson) {
		mosquitto_log_printf(MOSQ_LOG_WARNING, "[OAuth2 Plugin][W] Failed to parse data from introspection endpoint (MQTT Client ID: %s).", mqtt_client_id);
		free(buffer.data);
		return oauth2plugin_getMosquittoAuthError(_options->token_verification_error, data->client);
	}

	// Extract JSON fields and create oauth2plugin_strReplacementMap
	size_t replacement_map_count = oauth2plugin_oidc_template_placeholders_count;
	struct oauth2plugin_strReplacementMap replacement_map[replacement_map_count] = {};
	for (size_t i = 0; i < replacement_map_count; i++) {
		replacement_map[i].needle = oauth2plugin_oidc_template_placeholders[i].placeholder;
		cJSON* item = cJSON_GetObjectItemCaseSensitive(cjson, oauth2plugin_oidc_template_placeholders[i].oidc_key);
		if (cJSON_IsString(item)) {
			replacement_map[i].replacement = strdup(item->valuestring);
		} else {
			replacement_map[i].replacement = NULL;
		}
	}
	
	////
	// Step 3: Post OAuth2 validation
	////

	// Validate if token is active
	if (
		!oauth2plugin_isTokenActive(cjson)
	) {
		mosquitto_log_printf(MOSQ_LOG_INFO, "[OAuth2 Plugin][I] Token is not active (MQTT Client ID: %s).", mqtt_client_id);
		oauth2plugin_freeReplacementMap(replacement_map, replacement_map_count);
		cJSON_Delete(cjson);
		free(buffer.data);
		return oauth2plugin_getMosquittoAuthError(_options->token_verification_error, data->client);
	}
	
	// Validate username 
	if (
		_options->username_validation
		&& !oauth2plugin_isUsernameValid(
			mqtt_username,
			_options->username_validation_template,
			replacement_map,
			replacement_map_count
		)
	) {
		mosquitto_log_printf(MOSQ_LOG_INFO, "[OAuth2 Plugin][I] Username from MQTT client is not valid (MQTT Client ID: %s).", mqtt_client_id);
		oauth2plugin_freeReplacementMap(replacement_map, replacement_map_count);
		cJSON_Delete(cjson);
		free(buffer.data);
		return oauth2plugin_getMosquittoAuthError(_options->username_validation_error, data->client);
	}
	
	// Change username
	if (
		_options->username_replacement
		&& !oauth2plugin_setUsername(
			data->client,
			_options->username_replacement_template,
			replacement_map,
			replacement_map_count
		)
	) {
		mosquitto_log_printf(MOSQ_LOG_WARNING, "[OAuth2 Plugin][W] Error setting username (MQTT Client ID: %s).", mqtt_client_id);
		oauth2plugin_freeReplacementMap(replacement_map, replacement_map_count);
		cJSON_Delete(cjson);
		free(buffer.data);
		return oauth2plugin_getMosquittoAuthError(_options->username_replacement_error, data->client);

	}

	// Free objects
	oauth2plugin_freeReplacementMap(replacement_map, replacement_map_count);
	cJSON_Delete(cjson);
	free(buffer.data);
	
	// Return
	mosquitto_log_printf(MOSQ_LOG_INFO, "[OAuth2 Plugin][I] Authentication successful (MQTT Client ID: %s).", mqtt_client_id);
	return MOSQ_ERR_SUCCESS; // Access granted
	
}
