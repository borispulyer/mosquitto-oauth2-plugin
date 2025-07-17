# Mosquitto OAuth2 Plugin

This project provides an authentication plugin for the [Eclipse Mosquitto](https://mosquitto.org/) MQTT broker. Clients present an OAuth2 access token in the `password` field of the MQTT `CONNECT` packet. The plugin verifies the token using an OAuth2 *introspection* endpoint. If the token is valid (and optionally the reported username matches the MQTT username) the connection is accepted.

Using a simple template syntax, the plugin can check whether the supplied MQTT username matches information returned by the OAuth2 provider. The same mechanism also allows replacing the MQTT username with a new value derived from the introspection response before Mosquitto performs any ACL checks. This makes it possible to map OAuth2 identities to local usernames used in ACL files or other authorisation backends.

```
MQTT Client            Mosquitto Broker             OAuth2 Provider
     |                        |                            |
 1.  |--- CONNECT (token) --->|                            |
 2.  |                        |--- introspection request -->|
 3.  |                        |<-- token information -------|
 4.  |<-- CONNACK/ERROR ------|                            |
```

The diagram above illustrates the authentication flow. The client sends a `CONNECT` packet containing the access token, the plugin validates the token, optionally validates or rewrites the username and finally instructs Mosquitto to accept or deny the connection.

**Note:** The plugin only handles authentication. ACL checks are **not** implemented and can be configured via Mosquitto's `acl_file` mechanism.

## mosquitto.conf options
The plugin is configured through `plugin_opt_*` parameters in `mosquitto.conf`.

| Option | Description |
|-------|-------------|
| `introspection_endpoint` | URL of the OAuth2 introspection endpoint (required) |
| `client_id` | OAuth2 client identifier used for introspection (required) |
| `client_secret` | OAuth2 client secret (required) |
| `tls_verification` | `true` (default) to verify TLS certificates, `false` to disable verification |
| `timeout` | HTTP request timeout in seconds (default `5`) |
| `username_validation` | Enable username validation against `username_validation_template` (default `false`) |
| `username_validation_template` | Template that the MQTT username must match. Placeholders are replaced with values from the introspection response |
| `username_validation_error` | Behaviour when username validation fails: `deny` (default) or `defer` |
| `username_replacement` | Replace the MQTT username with `username_replacement_template` after successful authentication (default `false`) |
| `username_replacement_template` | Template used to create the new MQTT username after authentication |
| `username_replacement_error` | Behaviour when username replacement fails: `deny` (default) or `defer` |
| `token_verification_error` | Behaviour when token verification fails: `deny` (default) or `defer` |

The following placeholders can be used inside the username templates. They are replaced with values from the JSON document returned by the introspection endpoint:

- `%%oidc-username%%` – replaced with the value of the `username` claim
- `%%oidc-email%%` – replaced with the `email` claim
- `%%oidc-sub%%` – replaced with the `sub` (subject) claim
- `%%zitadel-role%%` – replaced with the first role name contained in the `urn:zitadel:iam:org:project:roles` claim. This is a ZITADEL specific extension and only the first role is used if multiple roles are present

### Example configuration
```conf
listener 1883
allow_anonymous false

plugin /mosquitto/plugins/oauth2-plugin.so
plugin_opt_introspection_endpoint https://auth.example.com/introspect
plugin_opt_client_id example-client
plugin_opt_client_secret example-secret
plugin_opt_tls_verification true
plugin_opt_username_validation true
plugin_opt_username_validation_template token-%%oidc-username%%
plugin_opt_username_replacement true
plugin_opt_username_replacement_template %%oidc-email%%
plugin_opt_timeout 5
```

## Docker compose usage
A `Dockerfile` is included that builds Mosquitto together with this plugin. The following `docker-compose.yml` shows how to build the image and run the broker:

```yaml
services:
  mosquitto:
    image: "mosquitto-oauth2:latest"
    build:
      context: "https://github.com/borispulyer/mosquitto-oauth2-plugin.git#main"
      dockerfile: "./Dockerfile"
    container_name: "mosquitto"
    restart: "unless-stopped"
    security_opt:
      - "no-new-privileges:true"
    ports:
      - "1883:1883"
    volumes:
      - "./mosquitto.conf:/mosquitto/config/mosquitto.conf:ro"
      - "./logs:/mosquitto/logs:rw"
      - "./data:/mosquitto/data:rw"
```

Place the example `mosquitto.conf` from above next to the compose file and start the broker with:

```sh
docker compose up --build
```

The plugin shared object will be available inside the container at `/mosquitto/plugins/oauth2-plugin.so`.
