# Spring Authorization Server

Customized from sample at [https://github.com/spring-projects/spring-authorization-server](https://github.com/spring-projects/spring-authorization-server).

## Usage

Start the server by running the class _com.example.spring.authorizationserver.SpringAuthorizationServerApplication_.

Look up the OAuth2/OIDC configuration from [http://localhost:9000/.well-known/openid-configuration](http://localhost:9000/.well-known/openid-configuration) to configure your clients and resource servers.

These are the most important configuration settings:

| Configuration Parameter | Value                                   | 
|-------------------------|-----------------------------------------|
| issuer                  | http://localhost:9000                   |
| authorization_endpoint  | http://localhost:9000/oauth2/authorize  |
| token_endpoint          | http://localhost:9000/oauth2/token      |
| jwks_uri                | http://localhost:9000/oauth2/jwks       |
| userinfo_endpoint       | http://localhost:9000/userinfo          |
| introspection_endpoint  | http://localhost:9000/oauth2/introspect |

## Registered Clients

This server comes with predefined registered OAuth2/OIDC clients:

| Client ID               | Client-Secret | PKCE | Access Token Format |
|-------------------------|---------------|------|---------------------|
| demo-client             | secret        | --   | JWT                 |
| demo-client-pkce        | secret        | X    | JWT                 |
| demo-client-opaque      | secret        | --   | Opaque              |
| demo-client-pkce-opaque | secret        | X    | Opaque              |

All clients have configured the following redirect URIs (including a special one for postman):

* http://127.0.0.1:9095/client/callback
* http://127.0.0.1:9095/client/authorized
* http://127.0.0.1:9095/client
* http://127.0.0.1:9095/login/oauth2/code/spring-authz-server
* https://oauth.pstmn.io/v1/callback

__Please note__: Instead of _localhost_ the local ip _127.0.0.1_ is configured as redirect URI. This is because spring security does not allow redirects of clients to localhost addresses.

## Login

This server already has preconfigured users.
Therefore, to login please use one of these predefined credentials:

| Username | Email                    | Password | Role   |
| ---------| ------------------------ | -------- |--------|
| bwayne   | bruce.wayne@example.com  | wayne    | USER   |
| ckent    | clark.kent@example.com   | kent     | USER   |
| pparker  | peter.parker@example.com | parker   | ADMIN  |

## Postman

You may use the provided postman collections to try the authorization server endpoints and the registered clients.
The collections (for both JWT and Opaque tokens) can be found in the _postman_ folder.

## Persistent Configuration Store

The authorization server uses a persistent H2 (in-memory) storage for configuration and stored tokens.

You may have a look inside the data using the [H2 console](http://localhost:9000/h2-console).

## Customizations

In the class _com.example.spring.authorizationserver.config.AuthorizationServerConfig_ you find some customizations.
As currently there is no documentation available for spring authorization server this may be helpful information.

### Configure information returned to the userinfo endpoint

```java
authorizationServerConfigurer.oidc(
                oidcConfigurer ->
                        oidcConfigurer.userInfoEndpoint(oidcUserInfoEndpointConfigurer ->
                                oidcUserInfoEndpointConfigurer.userInfoMapper(ac -> {
                                    Map<String, Object> claims = new HashMap<>();
                                    JwtAuthenticationToken jwtAuthenticationToken = (JwtAuthenticationToken) ac.getAuthentication().getPrincipal();
                                    claims.put("sub", jwtAuthenticationToken.getToken().getSubject());
                                    claims.put("name", jwtAuthenticationToken.getToken().getClaim("given_name") + " " +
                                            jwtAuthenticationToken.getToken().getClaim("family_name"));
                                    claims.put("family_name", jwtAuthenticationToken.getToken().getClaim("family_name"));
                                    claims.put("given_name", jwtAuthenticationToken.getToken().getClaim("given_name"));
                                    claims.put("email", jwtAuthenticationToken.getToken().getClaim("email"));
                                    claims.put("roles", jwtAuthenticationToken.getToken().getClaim("roles"));
                                    return new OidcUserInfo(claims);
                                }))
        );
```

### Customize id, access and refresh token contents

```java
@Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer() {
        return context -> {
            UsernamePasswordAuthenticationToken authentication = context.getPrincipal();
            LOGGER.info("Customizing {} for user {}", context.getTokenType(), authentication.getPrincipal());
            if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
                context.getHeaders().header("typ", "jwt");
                context.getClaims().subject(((User) authentication.getPrincipal()).getIdentifier().toString());
                context.getClaims().claim("roles", ((User) authentication.getPrincipal()).getRoles());
                context.getClaims().claim("given_name", ((User) authentication.getPrincipal()).getFirstName());
                context.getClaims().claim("family_name", ((User) authentication.getPrincipal()).getLastName());
                context.getClaims().claim("email", ((User) authentication.getPrincipal()).getEmail());
            } else if (OAuth2TokenType.REFRESH_TOKEN.equals(context.getTokenType())) {
                // Nothing to do here
            } else {
                context.getHeaders().header("typ", "jwt");
                context.getClaims().subject(((User) authentication.getPrincipal()).getIdentifier().toString());
                context.getClaims().claim("roles", ((User) authentication.getPrincipal()).getRoles());
                context.getClaims().claim("given_name", ((User) authentication.getPrincipal()).getFirstName());
                context.getClaims().claim("family_name", ((User) authentication.getPrincipal()).getLastName());
                context.getClaims().claim("email", ((User) authentication.getPrincipal()).getEmail());
            }
        };
    }
```