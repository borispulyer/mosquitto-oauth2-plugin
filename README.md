# Mosquitto OAuth2 Plugin

This project provides an authentication plugin for the [Eclipse Mosquitto](https://mosquitto.org/) MQTT broker. Clients present an OAuth2 access token in the `password` field of the MQTT `CONNECT` packet. The plugin then verifies the token by calling an OAuth2 *introspection* endpoint. If the endpoint confirms that the token is active (and optionally that the reported username matches the MQTT username) the connection is accepted.

**Note:** At the moment the plugin only handles authentication. It does **not** evaluate ACLs.

## mosquitto.conf options
The plugin is configured through `plugin_opt_*` parameters in `mosquitto.conf`.

| Option | Description |
|-------|-------------|
| `introspection_endpoint` | URL of the OAuth2 introspection endpoint (required) |
| `client_id` | OAuth2 client identifier used for introspection (required) |
| `client_secret` | OAuth2 client secret (required) |
| `verify_tls_certificate` | `true` (default) to verify TLS certificates, `false` to disable verification |
| `verify_username` | `true` (default) to check that the username returned by the endpoint matches the MQTT username |
| `timeout` | HTTP request timeout in seconds (default `5`) |

### Example configuration
```conf
listener 1883
allow_anonymous false

plugin /mosquitto/plugins/oauth2-plugin.so
plugin_opt_introspection_endpoint https://auth.example.com/introspect
plugin_opt_client_id example-client
plugin_opt_client_secret example-secret
plugin_opt_verify_tls_certificate true
plugin_opt_verify_username true
plugin_opt_timeout 5
```

## Docker compose usage
A Dockerfile is included (`v2.0.21.Dockerfile`) that builds Mosquitto together with this plugin. The following `docker-compose.yml` shows how to compile the image and run the broker:

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
