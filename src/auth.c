/**
 * auth.c
 * 
 * Handle OAuth2 authentication
 */

#include "auth.h"


static bool oauth2plugin_isUsernameValid(
	const enum oauth2plugin_Options_username_validation mode,
	const char* username,
	const char* template,
	const char* token
) {
	switch (mode) {
		case NONE: 
			return true;
			break;
		case OIDC_USERNAME: 
			return;
			break;
		case OIDC_EMAIL:
			return;
			break;
		case OIDC_SUB:
			return;
			break;
		case TEMPLATE:
			if (
				username
				&& template
				&& (strcmp(username, template) == 0)
			) {
				return true;
			}
			return;
			break;
		default: 
			return false;
			break;
	}
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


static int oauth2plugin_getIntrospectionResponse(
	const char* introspection_endpoint,
	const char* client_id,
	const char* client_secret,
	const char* token,
	const bool verify_tls_certificate,
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
	if (!verify_tls_certificate) {
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
	mosquitto_log_printf(MOSQ_LOG_DEBUG, "[OAuth2 Plugin][D]  - TLS: %s", verify_tls_certificate ? "<Enabled>" : "<Disabled>");
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


static bool oauth2plugin_isTokenValid(
	const char* introspection_response,
	const char* mqtt_username,
	char** oauth2_username
) {
	// Validate
	if (!introspection_response) return false;
	
	// Parse JSON
	cJSON* cjson = cJSON_Parse(introspection_response);
	if (!cjson) {
		mosquitto_log_printf(MOSQ_LOG_WARNING, "[OAuth2 Plugin][W] Failed to parse data from introspection endpoint.");
		return false;
	}

	// Step  1: Check for {"active": true}
	cJSON* cjson_active = cJSON_GetObjectItemCaseSensitive(cjson, "active");
	if (
		!cJSON_IsBool(cjson_active) 
		|| !cJSON_IsTrue(cjson_active)
	) {
		mosquitto_log_printf(MOSQ_LOG_DEBUG, "[OAuth2 Plugin][D] Introspection response is not {\"active\": true}. Token is not active.");
		cJSON_Delete(cjson);
		return false;
	}

	// Step  2: Validate username
	cJSON* cjson_username = cJSON_GetObjectItemCaseSensitive(cjson, "username");
	if (
		oauth2_username
		&& cJSON_IsString(cjson_username) 
	) {
		*oauth2_username = strdup(cjson_username->valuestring);
	}
	if (
		mqtt_username
		&& (
			!cJSON_IsString(cjson_username)
			|| !(strcmp(cjson_username->valuestring, mqtt_username) == 0)
		)
	) {
			mosquitto_log_printf(MOSQ_LOG_DEBUG, "[OAuth2 Plugin][D] OAuth2 username does not match username from MQTT client.");
			mosquitto_log_printf(MOSQ_LOG_DEBUG, "[OAuth2 Plugin][D]  - MQTT Client Username: %s", mqtt_username ? mqtt_username : "<none>");
			mosquitto_log_printf(MOSQ_LOG_DEBUG, "[OAuth2 Plugin][D]  - OAuth2 Username: %s", cjson_username->valuestring ? cjson_username->valuestring : "<none>");
			cJSON_Delete(cjson);
			return false;
	}
	
	// All checks passed -> return true
	cJSON_Delete(cjson);
	return true;
}


int oauth2plugin_callback_mosquittoBasicAuthentication(
	int event, 
	void* event_data, 
	void* userdata
) {
	// Unused Parameters
	(void) event;
	
	// Init
	struct oauth2plugin_Options* _options = (struct oauth2plugin_Options*) userdata;
	struct mosquitto_evt_basic_auth* data = (struct mosquitto_evt_basic_auth*) event_data;
	struct oauth2plugin_CURLBuffer buffer = { .data = NULL, .size = 0 };
	const char* mqtt_client_id = mosquitto_client_id(data->client);
	const char* mqtt_username  = mosquitto_client_username(data->client);
	const char* mqtt_password = data->password;

	// Log
	mosquitto_log_printf(MOSQ_LOG_DEBUG, "[OAuth2 Plugin][D] Starting client authentication.");
	mosquitto_log_printf(MOSQ_LOG_DEBUG, "[OAuth2 Plugin][D]  - MQTT Client ID: %s", mqtt_client_id);
	mosquitto_log_printf(MOSQ_LOG_DEBUG, "[OAuth2 Plugin][D]  - MQTT Client Username: %s", mqtt_username ? mqtt_username : "<none>");
	mosquitto_log_printf(MOSQ_LOG_DEBUG, "[OAuth2 Plugin][D]  - MQTT Client Password: %s", mqtt_password ? mqtt_password : "<none>");

	// Validate
	if (
		_options->mqtt_username
		&& !(strcmp(_options->mqtt_username, mqtt_username) == 0)
	) {
		mosquitto_log_printf(MOSQ_LOG_INFO, "[OAuth2 Plugin][I] MQTT Client Username does not match (MQTT Client ID: %s). Deferring authentication.", mqtt_client_id);
		mosquitto_log_printf(MOSQ_LOG_DEBUG, "[OAuth2 Plugin][D]  - MQTT Client Username: %s", mqtt_username ? mqtt_username : "<none>");
		mosquitto_log_printf(MOSQ_LOG_DEBUG, "[OAuth2 Plugin][D]  - Configured Username: %s", _options->mqtt_username ? _options->mqtt_username : "<none>");
		return MOSQ_ERR_PLUGIN_DEFER ; // Deferring authentication
	}
	if (mqtt_password == NULL) {
		mosquitto_log_printf(MOSQ_LOG_WARNING, "[OAuth2 Plugin][W] Empty password field -> No token to validate (MQTT Client ID: %s). Aborting authentication, authentication failed.", mqtt_client_id);
		return MOSQ_ERR_AUTH; // Access denied
	}

	// Call introspection endpoint
	int error = oauth2plugin_getIntrospectionResponse(
		_options->introspection_endpoint,
		_options->client_id,
		_options->client_secret,
		mqtt_password,
		_options->verify_tls_certificate,
		_options->timeout,
		&buffer
	);
	if (error) {
		mosquitto_log_printf(MOSQ_LOG_WARNING, "[OAuth2 Plugin][W] Failed to validate token (MQTT Client ID: %s). Aborting authentication, authentication failed.", mqtt_client_id);
		free(buffer.data);
		return MOSQ_ERR_AUTH; // Access denied
	}

	// Parse response from introspection endpoint
	bool is_token_valid = false;
	if (_options->verify_username) {
		is_token_valid = oauth2plugin_isTokenValid(buffer.data, mqtt_username, NULL);
	} 
	else if (_options->set_username_from_introspection) {
		char* oauth2_username = NULL;
		is_token_valid = oauth2plugin_isTokenValid(buffer.data, NULL, &oauth2_username);
		if (
			is_token_valid
			&& oauth2_username
			&& *oauth2_username
			&& (strlen(oauth2_username) > 0)
		) {
			mosquitto_log_printf(MOSQ_LOG_DEBUG, "[OAuth2 Plugin][D] Setting MQTT Client username to OAuth2 username.");
			mosquitto_log_printf(MOSQ_LOG_DEBUG, "[OAuth2 Plugin][D]  - New username: %s", oauth2_username ? oauth2_username : "<none>");
			mosquitto_set_username(data->client, oauth2_username);
		}
	}
	else {
		is_token_valid = oauth2plugin_isTokenValid(buffer.data, NULL, NULL);
	}
	free(buffer.data);
	
	// Return
	if (is_token_valid) {
		mosquitto_log_printf(MOSQ_LOG_INFO, "[OAuth2 Plugin][I] Authentication successful (MQTT Client ID: %s).", mqtt_client_id);
		return MOSQ_ERR_SUCCESS; // Access granted
	} else {
		mosquitto_log_printf(MOSQ_LOG_WARNING, "[OAuth2 Plugin][I] Authentication failed (MQTT Client ID: %s).", mqtt_client_id);
		return MOSQ_ERR_AUTH; // Access denied
	}
}