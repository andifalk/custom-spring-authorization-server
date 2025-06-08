[![License](https://img.shields.io/badge/License-Apache%20License%202.0-brightgreen.svg)][1]
![Build with Maven](https://github.com/andifalk/custom-spring-authorization-server/actions/workflows/build.yml/badge.svg)
![Code QL](https://github.com/andifalk/custom-spring-authorization-server/actions/workflows/codeql.yml/badge.svg)

# Spring Authorization Server

Customized from sample at [https://github.com/spring-projects/spring-authorization-server](https://github.com/spring-projects/spring-authorization-server).

## Requirements

To run this server you need at least a Java 21 runtime.

## Usage

Start the server by running the class `com.example.spring.authorizationserver.SpringAuthorizationServerApplication`.

Look up the OAuth2/OIDC configuration from [http://localhost:9500/.well-known/openid-configuration](http://localhost:9000/.well-known/openid-configuration) to configure your clients and resource servers.

These are the most important configuration settings:

| Configuration Parameter | Value                                   | 
|-------------------------|-----------------------------------------|
| issuer                  | http://localhost:9500                   |
| authorization_endpoint  | http://localhost:9500/oauth2/authorize  |
| token_endpoint          | http://localhost:9500/oauth2/token      |
| jwks_uri                | http://localhost:9500/oauth2/jwks       |
| userinfo_endpoint       | http://localhost:9500/userinfo          |
| introspection_endpoint  | http://localhost:9500/oauth2/introspect |

## Registered Clients

This server comes with predefined registered OAuth2/OIDC clients:

| Client ID                  | Client-Secret                     | PKCE | Grant(s)                                        | Access Token Format |
|----------------------------|-----------------------------------|------|-------------------------------------------------|---------------------|
| demo-client-jwt            | demo-client-jwt-secret            | --   | Authorization Code, Refresh Token               | JWT                 |
| demo-client-jwt-pkce       | demo-client-jwt-pkce-secret       | X    | Authorization Code                              | JWT                 |
| demo-client-token-exchange | demo-client-token-exchange-secret | --   | urn:ietf:params:oauth:grant-type:token-exchange | JWT                 |
| demo-client-credentials    | demo-client-credentials-secret    | --   | Client Credentials                              | JWT                 |
| demo-client-opaque         | demo-client-opaque-secret         | --   | Authorization Code                              | Opaque              |
| demo-client-opaque-pkce    | demo-client-opaque-pkce-secret    | X    | Authorization Code                              | Opaque              |

All interactive clients (using Authorization Code) have configured the following redirect URIs:

* Backends
  * http://127.0.0.1:8080/client/callback
  * http://127.0.0.1:8080/client/authorized
  * http://127.0.0.1:8080/client
  * http://127.0.0.1:8080/login/oauth2/code/spring-authz-server
  * http://localhost:8080/client/callback
  * http://localhost:8080/client/authorized
  * http://localhost:8080/client
  * http://localhost:8080/login/oauth2/code/spring-authz-server
* Postman 
  * https://oauth.pstmn.io/v1/callback
* Angular  
  * http://localhost:4200/login-callback
  * http://localhost:4200/index.html
  * http://localhost:4200/silent-refresh.html
  * http://localhost:4200/silent-renew.html
* React.js
  * http://localhost:3000/login-callback

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
        Function<OidcUserInfoAuthenticationContext, OidcUserInfo> userInfoMapper = (context) -> {
            OidcUserInfoAuthenticationToken authentication = context.getAuthentication();
            return new OidcUserInfo(oidcUserInfoService().loadUser(authentication.getName()).getClaims());
        };

        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer();
        RequestMatcher endpointsMatcher = authorizationServerConfigurer.getEndpointsMatcher();
        http.securityMatcher(endpointsMatcher).authorizeHttpRequests((authorize) ->
                authorize.anyRequest().authenticated()).csrf((csrf) -> {
            csrf.ignoringRequestMatchers(endpointsMatcher);
        }).with(authorizationServerConfigurer, withDefaults());
        authorizationServerConfigurer.oidc(
                o -> o
                        .providerConfigurationEndpoint(Customizer.withDefaults())
                        .clientRegistrationEndpoint(Customizer.withDefaults())
                        .userInfoEndpoint((userInfo) -> userInfo
                                .userInfoMapper(userInfoMapper)
                        )
        );	// Enable OpenID Connect 1.0

        http
                .exceptionHandling((exceptions) -> exceptions
                        .defaultAuthenticationEntryPointFor(
                                new LoginUrlAuthenticationEntryPoint("/login"),
                                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                        )
                )
                .oauth2ResourceServer((resourceServer) -> resourceServer
                        .opaqueToken(Customizer.withDefaults()));
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
            context.getJwsHeader().type("jwt");
            if (!AuthorizationGrantType.CLIENT_CREDENTIALS.equals(context.getAuthorizationGrantType())) {
                if (ID_TOKEN.equals(context.getTokenType().getValue()) || ACCESS_TOKEN.equals(context.getTokenType())) {
                    OidcUserInfo userInfo = userInfoService.loadUser(
                            context.getPrincipal().getName());
                    context.getClaims().claims(claims ->
                            claims.putAll(userInfo.getClaims()));
                    if (ACCESS_TOKEN.equals(context.getTokenType())) {
                        context.getClaims().audience(
                                List.of(
                                        context.getRegisteredClient().getClientId(),
                                        "demo-api"
                                )
                        );
                    }
                }
            }
        };
    }
}
```

## Testing the Authorization Server

You may use the http client requests located in the `requests` folder if you are using IntelliJ.

For testing this authorization server with client- or server applications, please use the corresponding GitHub repository for [Custom Spring Authorization Server Samples](https://github.com/andifalk/custom-spring-authorization-server-samples).

This includes a demo OAuth client and resource server.

## Feedback

Any feedback on this project is highly appreciated.

Just email _andreas.falk(at)novatec-gmbh.de_ or contact me via Twitter (_@andifalk_).

## License

Apache 2.0 licensed

[1]:http://www.apache.org/licenses/LICENSE-2.0.txt