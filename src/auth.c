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
			mosquitto_log_printf(MOSQ_LOG_INFO, "[OAuth2 Plugin][I] Authentication failed. ACCESS DENIED. (MQTT Client ID: %s).", mqtt_client_id);
			return MOSQ_ERR_AUTH; // Access denied
			break;
		case verification_error_DEFER:
			mosquitto_log_printf(MOSQ_LOG_INFO, "[OAuth2 Plugin][I] Authentication failed. Deferring authentication (MQTT Client ID: %s).", mqtt_client_id);
			return MOSQ_ERR_PLUGIN_DEFER; // Deferring authentication
			break;
	}
	return MOSQ_ERR_AUTH; // Access denied
}


static bool oauth2plugin_isUsernameValid_preOAuth2(
	const char* username,
	const enum oauth2plugin_Options_username_validation username_validation,
	const char* username_validation_template
) {
	switch (username_validation) {

		// No Validation
		case username_validation_NONE:
			return true;
			break;

		// Username must match some OIDC field
		// Cannot be checked before OAuth2 request, but username must not be empty
		case username_validation_OIDC_USERNAME: 
		case username_validation_OIDC_EMAIL:
		case username_validation_OIDC_SUB:
			// Validate
			if (username != NULL) 
				return true;
			
			// Username is empty
			mosquitto_log_printf(MOSQ_LOG_DEBUG, "[OAuth2 Plugin][D] Username from MQTT client is empty.");
			mosquitto_log_printf(MOSQ_LOG_DEBUG, "[OAuth2 Plugin][D]  - MQTT Client Username: %s", username ? username : "<none>");
			mosquitto_log_printf(MOSQ_LOG_DEBUG, "[OAuth2 Plugin][D]  - Username Verification: <%s>", oauth2plugin_Options_username_validation_toString(username_validation));
			return false;
			break;

		// Username must match template from config file
		case username_validation_TEMPLATE:
			// Validate
			if (
				username
				&& username_validation_template
				&& (strcmp(username, username_validation_template) == 0)
			) return true;
			
			// Usernames do not match
			mosquitto_log_printf(MOSQ_LOG_DEBUG, "[OAuth2 Plugin][D] Username from MQTT client does not match username template in config file.");
			mosquitto_log_printf(MOSQ_LOG_DEBUG, "[OAuth2 Plugin][D]  - MQTT Client Username: %s", username ? username : "<none>");
			mosquitto_log_printf(MOSQ_LOG_DEBUG, "[OAuth2 Plugin][D]  - Username Verification: <%s>", oauth2plugin_Options_username_validation_toString(username_validation));
			mosquitto_log_printf(MOSQ_LOG_DEBUG, "[OAuth2 Plugin][D]  - Username Verification Template: %s", username_validation_template ? username_validation_template : "<None>");
			return false;
			break;

		default: 
			return false;
			break;
	}
	return false;
}


static bool oauth2plugin_isUsernameValid_postOAuth2(
	const char* username,
	const cJSON* introspection_response,
	const enum oauth2plugin_Options_username_validation username_validation,
	const char* username_validation_template
) {
	switch (username_validation) {

		// No Validation
		case username_validation_NONE: 
			return true;
			break;

		// Username must match OIDC field "username"
		case username_validation_OIDC_USERNAME:
			// Validate
			if (
				!username
				|| !introspection_response
			) return false;
			
			// Check username from OAuth2 response
			cJSON* cjson_username = cJSON_GetObjectItemCaseSensitive(introspection_response, "username");
			if (
				cJSON_IsString(cjson_username)
				&& (strcmp(cjson_username->valuestring, username) == 0)
			) return true;
			
			// Usernames do not match
			mosquitto_log_printf(MOSQ_LOG_DEBUG, "[OAuth2 Plugin][D] Username from MQTT client does not match value of \"username\" from OAuth2 response.");
			mosquitto_log_printf(MOSQ_LOG_DEBUG, "[OAuth2 Plugin][D]  - MQTT Client Username: %s", username ? username : "<none>");
			mosquitto_log_printf(MOSQ_LOG_DEBUG, "[OAuth2 Plugin][D]  - OAuth2 \"username\": %s", cjson_username->valuestring ? cjson_username->valuestring : "<none>");
			return false;
			break;

		// Username must match OIDC field "email"
		case username_validation_OIDC_EMAIL:
			// Validate
			if (
				!username
				|| !introspection_response
			) return false;
			
			// Check username from OAuth2 response
			cJSON* cjson_email = cJSON_GetObjectItemCaseSensitive(introspection_response, "email");
			if (
				cJSON_IsString(cjson_email)
				&& (strcmp(cjson_email->valuestring, username) == 0)
			) return true;
			
			// Usernames do not match
			mosquitto_log_printf(MOSQ_LOG_DEBUG, "[OAuth2 Plugin][D] Username from MQTT client does not match value of \"email\" from OAuth2 response.");
			mosquitto_log_printf(MOSQ_LOG_DEBUG, "[OAuth2 Plugin][D]  - MQTT Client Username: %s", username ? username : "<none>");
			mosquitto_log_printf(MOSQ_LOG_DEBUG, "[OAuth2 Plugin][D]  - OAuth2 \"email\": %s", cjson_email->valuestring ? cjson_email->valuestring : "<none>");
			return false;
			break;

		// Username must match OIDC field "sub" (Subject)
		case username_validation_OIDC_SUB:
			// Validate
			if (
				!username
				|| !introspection_response
			) return false;
			
			// Check username from OAuth2 response
			cJSON* cjson_sub = cJSON_GetObjectItemCaseSensitive(introspection_response, "sub");
			if (
				cJSON_IsString(cjson_sub)
				&& (strcmp(cjson_sub->valuestring, username) == 0)
			) return true;
			
			// Usernames do not match
			mosquitto_log_printf(MOSQ_LOG_DEBUG, "[OAuth2 Plugin][D] Username from MQTT client does not match value of \"sub\" from OAuth2 response.");
			mosquitto_log_printf(MOSQ_LOG_DEBUG, "[OAuth2 Plugin][D]  - MQTT Client Username: %s", username ? username : "<none>");
			mosquitto_log_printf(MOSQ_LOG_DEBUG, "[OAuth2 Plugin][D]  - OAuth2 \"sub\": %s", cjson_sub->valuestring ? cjson_sub->valuestring : "<none>");
			return false;
			break;

		// Username must match template from config file
		case username_validation_TEMPLATE:
			return true;
			break;
		
		default: 
			return false;
			break;
	}
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
	const cJSON* introspection_response,
	const enum oauth2plugin_Options_username_replacement username_replacement,
	const char* username_replacement_template
) {
	// Validate
	if (!client) return false;


	switch (username_replacement) {

		// No replacement
		case username_replacement_NONE: 
			return true;
			break;

		// Replace username with OIDC field "username"
		case username_replacement_OIDC_USERNAME:
			// Validate
			if (!introspection_response) return false;
			
			// Replace username
			cJSON* cjson_username = cJSON_GetObjectItemCaseSensitive(introspection_response, "username");
			if (cJSON_IsString(cjson_username)) {
				mosquitto_log_printf(MOSQ_LOG_DEBUG, "[OAuth2 Plugin][D] Replacing username with OIDC field \"username\".");
				mosquitto_log_printf(MOSQ_LOG_DEBUG, "[OAuth2 Plugin][D]  - New username: %s", cjson_username->valuestring ? cjson_username->valuestring : "<none>");
				mosquitto_set_username(client, cjson_username->valuestring);
				return true;
			}
			return false;
			break;

		// Replace username with OIDC field "email"
		case username_replacement_OIDC_EMAIL:
			// Validate
			if (!introspection_response) return false;
			
			// Replace username
			cJSON* cjson_email = cJSON_GetObjectItemCaseSensitive(introspection_response, "email");
			if (cJSON_IsString(cjson_email)) {
				mosquitto_log_printf(MOSQ_LOG_DEBUG, "[OAuth2 Plugin][D] Replacing username with OIDC field \"email\".");
				mosquitto_log_printf(MOSQ_LOG_DEBUG, "[OAuth2 Plugin][D]  - New username: %s", cjson_email->valuestring ? cjson_email->valuestring : "<none>");
				mosquitto_set_username(client, cjson_email->valuestring);
				return true;
			}
			return false;
			break;

		// Replace username with OIDC field "sub" (Subject)
		case username_replacement_OIDC_SUB:
			// Validate
			if (!introspection_response) return false;
			
			// Replace username
			cJSON* cjson_sub = cJSON_GetObjectItemCaseSensitive(introspection_response, "sub");
			if (cJSON_IsString(cjson_sub)) {
				mosquitto_log_printf(MOSQ_LOG_DEBUG, "[OAuth2 Plugin][D] Replacing username with OIDC field \"sub\".");
				mosquitto_log_printf(MOSQ_LOG_DEBUG, "[OAuth2 Plugin][D]  - New username: %s", cjson_sub->valuestring ? cjson_sub->valuestring : "<none>");
				mosquitto_set_username(client, cjson_sub->valuestring);
				return true;
			}
			return false;
			break;

		// Replace username with template from config file
		case username_replacement_TEMPLATE:
			// Validate
			if (!username_replacement_template) return false;
			
			// Replace username
			mosquitto_log_printf(MOSQ_LOG_DEBUG, "[OAuth2 Plugin][D] Replacing username with template from config file.");
			mosquitto_log_printf(MOSQ_LOG_DEBUG, "[OAuth2 Plugin][D]  - New username: %s", username_replacement_template ? username_replacement_template : "<none>");
			mosquitto_set_username(client, username_replacement_template);
			return true;
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

	// Step 1: Pre OAuth2 request
	// Validate username before performing OAuth2 request
	if (
		!oauth2plugin_isUsernameValid_preOAuth2(
			mqtt_username,
			_options->username_validation,
			_options->username_validation_template
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

	// Step 2: Performing OAuth2 request
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
	
	// Step 3: Post OAuth2 request
	// Validate if token is active
	if (
		!oauth2plugin_isTokenActive(cjson)
	) {
		mosquitto_log_printf(MOSQ_LOG_INFO, "[OAuth2 Plugin][I] Token is not active (MQTT Client ID: %s).", mqtt_client_id);
		cJSON_Delete(cjson);
		free(buffer.data);
		return oauth2plugin_getMosquittoAuthError(_options->token_verification_error, data->client);
	}
	
	// Validate username after performing OAuth2 request
	if (
		!oauth2plugin_isUsernameValid_postOAuth2(
			mqtt_username,
			cjson,
			_options->username_validation,
			_options->username_validation_template
		)
	) {
		mosquitto_log_printf(MOSQ_LOG_INFO, "[OAuth2 Plugin][I] Username from MQTT client is not valid (MQTT Client ID: %s).", mqtt_client_id);
		cJSON_Delete(cjson);
		free(buffer.data);
		return oauth2plugin_getMosquittoAuthError(_options->username_validation_error, data->client);
	}
	
	// Change username
	if (
		!oauth2plugin_setUsername(
			data->client,
			cjson,
			_options->username_replacement,
			_options->username_replacement_template

		)
	) {
		mosquitto_log_printf(MOSQ_LOG_WARNING, "[OAuth2 Plugin][W] Error setting username (MQTT Client ID: %s).", mqtt_client_id);
		cJSON_Delete(cjson);
		free(buffer.data);
		return oauth2plugin_getMosquittoAuthError(_options->username_replacement_error, data->client);

	}

	// Free objects
	cJSON_Delete(cjson);
	free(buffer.data);
	
	// Return
	mosquitto_log_printf(MOSQ_LOG_INFO, "[OAuth2 Plugin][I] Authentication successful (MQTT Client ID: %s).", mqtt_client_id);
	return MOSQ_ERR_SUCCESS; // Access granted
	
}