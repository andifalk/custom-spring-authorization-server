[![License](https://img.shields.io/badge/License-Apache%20License%202.0-brightgreen.svg)][1]
![Java CI with Gradle](https://github.com/andifalk/custom-spring-authorization-server/workflows/build.yml/badge.svg)
![Code QL](https://github.com/andifalk/custom-spring-authorization-server/workflows/codeql.yml/badge.svg)

# Spring Authorization Server

Customized from sample at [https://github.com/spring-projects/spring-authorization-server](https://github.com/spring-projects/spring-authorization-server).

## Requirements

To run this server you need at least a Java 17 runtime as this project uses spring boot 3.x.

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

| Client ID               | Client-Secret | PKCE | Client-Credentials Grant | Access Token Format |
|-------------------------|---------------|------|--------------------------|---------------------|
| demo-client             | secret        | --   | X                        | JWT                 |
| demo-client-pkce        | --            | X    | --                       | JWT                 |
| demo-client-opaque      | secret        | --   | X                        | Opaque              |
| demo-client-pkce-opaque | --            | X    | --                       | Opaque              |

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

| Username | Email                    | Password | Roles       |
|----------|--------------------------|----------|-------------|
| bwayne   | bruce.wayne@example.com  | wayne    | USER        |
| ckent    | clark.kent@example.com   | kent     | USER        |
| pparker  | peter.parker@example.com | parker   | USER, ADMIN |

## Postman

You may use the provided postman collections to try the authorization server endpoints and the registered clients.
The collections (for both JWT and Opaque tokens) can be found in the _postman_ folder.

## Persistent Configuration Store

The authorization server uses a persistent H2 (in-memory) storage for configuration and stored tokens.

You may have a look inside the data using the [H2 console](http://localhost:9000/h2-console).
Please use ```jdbc:h2:mem:authzserver``` as jdbc url and _sa_ as username, leave password empty.

## Customizations

This customized version contains an extended `user` object compared to the standard spring security `user` object.
The contents of id and access tokens and user info endpoint information is customized for extended user data as well.

Check the spring [authorization server reference docs](https://docs.spring.io/spring-authorization-server/docs/current/reference/html/guides/how-to-userinfo.html) for more information.

### Configure information returned to the userinfo endpoint

__com.example.spring.authorizationserver.config.AuthorizationServerConfig:__

```java
@Configuration(proxyBeanMethods = false)
public class AuthorizationServerConfig {
    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE + 1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
                new OAuth2AuthorizationServerConfigurer();
        RequestMatcher endpointsMatcher = authorizationServerConfigurer
                .getEndpointsMatcher();

        Function<OidcUserInfoAuthenticationContext, OidcUserInfo> userInfoMapper = (context) -> {
            OidcUserInfoAuthenticationToken authentication = context.getAuthentication();
            JwtAuthenticationToken principal = (JwtAuthenticationToken) authentication.getPrincipal();

            return new OidcUserInfo(principal.getToken().getClaims());
        };

        authorizationServerConfigurer
                .oidc((oidc) -> oidc
                        .userInfoEndpoint((userInfo) -> userInfo
                                .userInfoMapper(userInfoMapper)
                        )
                );
        http
                .securityMatcher(endpointsMatcher)
                .authorizeHttpRequests((authorize) -> authorize
                        .anyRequest().authenticated()
                )
                .csrf(csrf -> csrf.ignoringRequestMatchers(endpointsMatcher))
                .exceptionHandling(exceptions ->
                        exceptions.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))
                )
                .oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt)
                .apply(authorizationServerConfigurer);
        return http.build();
    }
}
```

### Customize id and access token contents

```java
@Configuration
public class JwtTokenCustomizerConfig {
    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer(OidcUserInfoService userInfoService) {
        return (context) -> {
            if (ID_TOKEN.equals(context.getTokenType().getValue()) || ACCESS_TOKEN.equals(context.getTokenType())) {
                OidcUserInfo userInfo = userInfoService.loadUser(
                        context.getPrincipal().getName());
                context.getClaims().claims(claims ->
                        claims.putAll(userInfo.getClaims()));
            }
        };
    }
}
```

## Testing the Authorization Server

For testing this authorization server with client- or server applications please use the corresponding GitHub repository for [Custom Spring Authorization Server Samples](https://github.com/andifalk/custom-spring-authorization-server-samples).

This includes a demo OAuth client and resource server.

## Feedback

Any feedback on this project is highly appreciated.

Just email _andreas.falk(at)novatec-gmbh.de_ or contact me via Twitter (_@andifalk_).

## License

Apache 2.0 licensed

[1]:http://www.apache.org/licenses/LICENSE-2.0.txt