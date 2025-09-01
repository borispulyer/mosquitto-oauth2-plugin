# Mosquitto OAuth2 Plugin

This project provides an authentication plugin for the [Eclipse Mosquitto](https://mosquitto.org/) MQTT broker. Clients present an OAuth2 access token in the `password` field of the MQTT `CONNECT` packet. The plugin verifies the given token using an OAuth2 _introspection endpoint_. It can also verify, if the given username matches a preconfigured template. If the token and optionally the username are valid, the connection is accepted.

Using a simple template syntax, the plugin can check whether the supplied MQTT username matches information returned by the OAuth2 provider. The same mechanism also allows replacing the MQTT username with a new value derived from the introspection response before Mosquitto performs any ACL checks. This makes it possible to map OAuth2 identities to local usernames used in ACL files or other authorisation backends.

```
MQTT Client            Mosquitto Broker                 OAuth2 Provider
     |                        |                                 |
 1.  |--- CONNECT (token) --->|                                 |
 2.  |                        |-- check username (pre)          |
 3.  |                        |----- introspection request ---->|
 4.  |                        |<---- token information ---------|
 5.  |                        |-- verify token                  |
 6.  |                        |-- check username (post)         |
 7.  |                        |-- modify username               |
 8.  |                        |-- ACL checks                    |
 9.  |<-- CONNACK/ERROR ------|                                 |
```

The diagram above illustrates the authentication flow. After receiving the `CONNECT` packet the plugin can first validate the presented MQTT username. It then calls the OAuth2 _introspection endpoint_ to verify the token, checks the username again using the returned claims, optionally replaces it and finally hands control back to Mosquitto which performs any configured ACL checks before accepting or rejecting the connection.

**Note:** The plugin only handles authentication. ACL checks are **not** implemented and can be configured via Mosquitto's `acl_file` mechanism.

**Note:** The plugin (yet) cannot verify JSON Web Token (JWT) using public keys. The verification is done by calling the introspection endpoint of the Identity Provider.

## mosquitto.conf options

The plugin is configured through `plugin_opt_*` parameters in `mosquitto.conf`.

| Option                          | Description                                                                                                                                       |
| ------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| `introspection_endpoint`        | URL of the OAuth2 introspection endpoint (required)                                                                                               |
| `client_id`                     | OAuth2 client identifier used for introspection (required)                                                                                        |
| `client_secret`                 | OAuth2 client secret (required)                                                                                                                   |
| `tls_verification`              | `true` to verify TLS certificates, `false` to disable verification (default `true`)                                                               |
| `timeout`                       | HTTP request timeout in seconds (default `5`)                                                                                                     |
| `username_validation`           | Enable username validation against `username_validation_template` (`true` or `false`, default `false`)                                            |
| `username_validation_template`  | Template string that the MQTT username must match. Placeholders (see below) are replaced with values from the introspection response.             |
| `username_validation_error`     | Behaviour when username validation fails: `deny` access or `defer` authentication to other mechanisms, e.g. `mosquitto_passwd` (default `defer`). |
| `username_replacement`          | Replace the MQTT username with `username_replacement_template` after successful authentication (`true` or `false`, default `false`).              |
| `username_replacement_template` | Template string used to create the new MQTT username after authentication before Mosquitto performs any ACL checks.                               |
| `username_replacement_error`    | Behaviour when username replacement fails: `deny` access or `defer` authentication to other mechanisms, e.g. `mosquitto_passwd` (default `deny`). |
| `token_verification_error`      | Behaviour when token verification fails: `deny` access or `defer` authentication to other mechanisms, e.g. `mosquitto_passwd` (default `deny`).   |

The following placeholders can be used inside the username templates. They are replaced with values from the JSON document returned by the introspection endpoint:

- `%%oidc-username%%` – replaced with the value of the `username` claim
- `%%oidc-email%%` – replaced with the `email` claim
- `%%oidc-sub%%` – replaced with the `sub` (subject) claim
- `%%zitadel-role%%` – replaced with the (first) [role name](https://zitadel.com/docs/guides/integrate/retrieve-user-roles) contained in the `urn:zitadel:iam:org:project:roles` claim. This is a [ZITADEL](https://zitadel.com/) specific extension and only the first role is used if multiple roles are present

### Example configuration

```conf
listener 1883
allow_anonymous false

plugin /mosquitto/plugins/oauth2-plugin.so
plugin_opt_introspection_endpoint https://auth.example.com/introspect
plugin_opt_client_id 1234556789
plugin_opt_client_secret YouRSEcretKey
plugin_opt_tls_verification true
plugin_opt_timeout 5
plugin_opt_username_validation true
plugin_opt_username_validation_template token
plugin_opt_username_validation_error defer
plugin_opt_username_replacement true
plugin_opt_username_replacement_template user-%%oidc-username%%
plugin_opt_username_replacement_error deny
plugin_opt_token_verification_error deny
```

### Template examples

The plugin allows flexible username validation and replacement. Below are several typical configurations demonstrating how templates can be used.

#### Enable OAuth2 validation only for specific usernames

```conf
plugin_opt_username_validation true
plugin_opt_username_validation_template oauth2-token
plugin_opt_username_validation_error defer
```

The plugin will only validate the token against the OAuth2 server, if the `username` is set to `oauth2-token`. Otherwise the plugin will defer the authentication, hence other users can also be authenticated by a `passwd` file.

#### Validate username using the `username` claim

```conf
plugin_opt_username_validation true
plugin_opt_username_validation_template user-%%oidc-username%%
plugin_opt_username_validation_error deny
```

The client must connect with a username matching `user-<username>` where `<username>` is taken from the introspection response. Otherwise the authentication false.

#### Replace the username with the user's email address

```conf
plugin_opt_username_validation true
plugin_opt_username_validation_template oauth2-token
plugin_opt_username_validation_error defer
plugin_opt_username_replacement true
plugin_opt_username_replacement_template %%oidc-email%%
plugin_opt_username_replacement_error deny
```

The plugin will only validate the token against the OAuth2 server, if the `username` is set to `oauth2-token`. Otherwise the plugin will defer the authentication. If the validation of the token is successful, the plugin will replace the client's username with the `<email>`taken from the introspection response. This might be useful when ACLs expects the email adress of the user.

#### Use ZITADEL's role as username

```conf
plugin_opt_username_replacement true
plugin_opt_username_replacement_template group-%%zitadel-role%%
plugin_opt_username_replacement_error deny
```

This is a placeholder specific for ZITADEL identity servers. The (first) [role returned by ZITADEL](https://zitadel.com/docs/guides/integrate/retrieve-user-roles) is used for the username.

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
