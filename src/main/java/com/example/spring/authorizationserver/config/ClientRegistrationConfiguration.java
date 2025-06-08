package com.example.spring.authorizationserver.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import java.time.Duration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import static org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat.SELF_CONTAINED;

@Configuration
public class ClientRegistrationConfiguration {

    private static final Logger LOGGER = LoggerFactory.getLogger(ClientRegistrationConfiguration.class);

    public static final String CLIENT_ID_DEMO_CLIENT_TOKEN_EXCHANGE = "demo-client-token-exchange";
    public static final String CLIENT_ID_DEMO_CLIENT_PKCE_OPAQUE = "demo-client-opaque-pkce";
    public static final String CLIENT_ID_DEMO_CLIENT_OPAQUE = "demo-client-opaque";
    public static final String CLIENT_ID_DEMO_CLIENT_JWT_PKCE = "demo-client-jwt-pkce";
    public static final String CLIENT_ID_DEMO_CLIENT_JWT = "demo-client-jwt";
    public static final String CLIENT_ID_DEMO_CLIENT_CREDENTIALS = "demo-client-credentials";

    private static final String CLIENT_SECRET_DEMO_CLIENT_TOKEN_EXCHANGE = "demo-client-token-exchange-secret";
    private static final String CLIENT_SECRET_DEMO_CLIENT_PKCE_OPAQUE = "demo-client-opaque-pkce-secret";
    private static final String CLIENT_SECRET_DEMO_CLIENT_OPAQUE = "demo-client-opaque-secret";
    private static final String CLIENT_SECRET_DEMO_CLIENT_JWT_PKCE = "demo-client-jwt-pkce-secret";
    private static final String CLIENT_SECRET_DEMO_CLIENT_JWT = "demo-client-jwt-secret";
    private static final String CLIENT_SECRET_DEMO_CLIENT_CREDENTIALS = "demo-client-credentials-secret";

    private static final String SCOPE_OFFLINE_ACCESS = "offline_access";


    private static Set<String> getRedirectUris() {
        Set<String> redirectUris = new HashSet<>();

        // Backend URLs
        redirectUris.add("http://127.0.0.1:8080/client/callback");
        redirectUris.add("http://127.0.0.1:8080/client");
        redirectUris.add("http://127.0.0.1:8080/login/oauth2/code/spring");
        redirectUris.add("http://127.0.0.1:8080/client/login/oauth2/code/spring");
        redirectUris.add("http://localhost:8080/client/callback");
        redirectUris.add("http://localhost:8080/client");
        redirectUris.add("http://localhost:8080/login/oauth2/code/spring");
        redirectUris.add("http://localhost:8080/client/login/oauth2/code/spring");

        // Angular Callback
        redirectUris.add("http://localhost:4200/login-callback");
        redirectUris.add("http://localhost:4200/index.html");
        redirectUris.add("http://localhost:4200/silent-refresh.html");
        redirectUris.add("http://localhost:4200/silent-renew.html");

        // React Callback
        redirectUris.add("http://localhost:3000/login-callback");

        // Postman URL
        redirectUris.add("https://oauth.pstmn.io/v1/callback");
        return redirectUris;
    }

    /*
     * Repository with all registered OAuth/OIDC clients.
     */
    @Bean
    public RegisteredClientRepository registeredClientRepository(PasswordEncoder passwordEncoder) {
        Set<String> redirectUris = getRedirectUris();

        RegisteredClient demoClient = getDemoClientJWT(passwordEncoder, redirectUris);

        RegisteredClient demoClientPKCE = getDemoClientJWTWithPKCE(passwordEncoder, redirectUris);

        RegisteredClient demoClientOpaque = getDemoClientOpaque(passwordEncoder, redirectUris);

        RegisteredClient demoClientPKCEOpaque = getDemoClientOpaqueWithPKCE(passwordEncoder, redirectUris);

        RegisteredClient demoClientTokenExchange = getDemoClientTokenExchange(passwordEncoder);

        RegisteredClient demoClientCredentials = getDemoClientCredentials(passwordEncoder);

        LOGGER.info("Add {}", demoClient);
        LOGGER.info("Add {}", demoClientPKCE);
        LOGGER.info("Add {}", demoClientOpaque);
        LOGGER.info("Add {}", demoClientPKCEOpaque);
        LOGGER.info("Add {}", demoClientTokenExchange);
        LOGGER.info("Add {}", demoClientCredentials);

        // Save registered client in db as if in-memory
        return new InMemoryRegisteredClientRepository(
                demoClient, demoClientPKCE, demoClientOpaque,
                demoClientPKCEOpaque, demoClientTokenExchange, demoClientCredentials
        );
    }

    private static RegisteredClient getDemoClientTokenExchange(PasswordEncoder passwordEncoder) {
        return
                RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(CLIENT_ID_DEMO_CLIENT_TOKEN_EXCHANGE)
                .clientSecret(passwordEncoder.encode(CLIENT_SECRET_DEMO_CLIENT_TOKEN_EXCHANGE))
                .clientAuthenticationMethods(methods -> methods.addAll(
                        List.of(
                                ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
                                ClientAuthenticationMethod.CLIENT_SECRET_POST
                        )
                ))
                .authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
                .tokenSettings(TokenSettings.builder().accessTokenFormat(SELF_CONTAINED)
                        .accessTokenTimeToLive(Duration.ofHours(8)).build())
                .scopes(scopes -> scopes.addAll(List.of(
                        OidcScopes.OPENID, OidcScopes.PROFILE, OidcScopes.EMAIL
                )))
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(false).requireProofKey(false).build())
                .build();
    }


    private static RegisteredClient getDemoClientOpaqueWithPKCE(PasswordEncoder passwordEncoder, Set<String> redirectUris) {
        return RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(CLIENT_ID_DEMO_CLIENT_PKCE_OPAQUE)
                .clientSecret(passwordEncoder.encode(CLIENT_SECRET_DEMO_CLIENT_PKCE_OPAQUE))
                .clientAuthenticationMethods(methods -> methods.addAll(
                        List.of(
                                ClientAuthenticationMethod.NONE,
                                ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
                                ClientAuthenticationMethod.CLIENT_SECRET_POST
                        )
                ))
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .tokenSettings(TokenSettings.builder().accessTokenFormat(OAuth2TokenFormat.REFERENCE)
                        .accessTokenTimeToLive(Duration.ofMinutes(15))
                        .authorizationCodeTimeToLive(Duration.ofMinutes(2)).reuseRefreshTokens(false).build())
                .redirectUris(uris -> {
                    uris.addAll(redirectUris);
                })
                .scopes(scopes -> scopes.addAll(List.of(
                        OidcScopes.OPENID, OidcScopes.PROFILE, OidcScopes.EMAIL, SCOPE_OFFLINE_ACCESS
                )))
                .clientSettings(ClientSettings.builder().requireProofKey(true).requireAuthorizationConsent(false).build())
                .build();
    }

    private static RegisteredClient getDemoClientOpaque(PasswordEncoder passwordEncoder, Set<String> redirectUris) {
        return
                RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(CLIENT_ID_DEMO_CLIENT_OPAQUE)
                .clientSecret(passwordEncoder.encode(CLIENT_SECRET_DEMO_CLIENT_OPAQUE))
                .clientAuthenticationMethods(methods -> methods.addAll(
                        List.of(
                                ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
                                ClientAuthenticationMethod.CLIENT_SECRET_POST
                        )))
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .tokenSettings(TokenSettings.builder().accessTokenFormat(OAuth2TokenFormat.REFERENCE)
                        .accessTokenTimeToLive(Duration.ofMinutes(15))
                        .authorizationCodeTimeToLive(Duration.ofMinutes(2)).reuseRefreshTokens(false).build())
                .redirectUris(uris -> uris.addAll(redirectUris))
                .scopes(scopes -> scopes.addAll(List.of(
                        OidcScopes.OPENID, OidcScopes.PROFILE, OidcScopes.EMAIL, SCOPE_OFFLINE_ACCESS
                )))
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(false).build())
                .build();
    }

    private static RegisteredClient getDemoClientJWTWithPKCE(PasswordEncoder passwordEncoder, Set<String> redirectUris) {
        return
                RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(CLIENT_ID_DEMO_CLIENT_JWT_PKCE)
                .clientSecret(passwordEncoder.encode(CLIENT_SECRET_DEMO_CLIENT_JWT_PKCE))
                .clientAuthenticationMethods(methods -> methods.addAll(
                        List.of(
                                ClientAuthenticationMethod.NONE,
                                ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
                                ClientAuthenticationMethod.CLIENT_SECRET_POST
                        ))
                )
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .tokenSettings(TokenSettings.builder().accessTokenFormat(SELF_CONTAINED)
                        .accessTokenTimeToLive(Duration.ofMinutes(15))
                        .authorizationCodeTimeToLive(Duration.ofMinutes(2)).reuseRefreshTokens(false).build())
                .redirectUris(uris -> uris.addAll(redirectUris))
                .scopes(scopes -> scopes.addAll(List.of(
                        OidcScopes.OPENID, OidcScopes.PROFILE, OidcScopes.EMAIL, SCOPE_OFFLINE_ACCESS
                )))
                .clientSettings(ClientSettings.builder().requireProofKey(true).requireAuthorizationConsent(false).build())
                .build();
    }

    private static RegisteredClient getDemoClientJWT(PasswordEncoder passwordEncoder, Set<String> redirectUris) {
        return
                RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(CLIENT_ID_DEMO_CLIENT_JWT)
                .clientSecret(passwordEncoder.encode(CLIENT_SECRET_DEMO_CLIENT_JWT))
                .clientAuthenticationMethods(methods -> methods.addAll(
                        List.of(
                                ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
                                ClientAuthenticationMethod.CLIENT_SECRET_POST
                        )))
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .tokenSettings(TokenSettings.builder().accessTokenFormat(SELF_CONTAINED)
                        .accessTokenTimeToLive(Duration.ofMinutes(15))
                        .authorizationCodeTimeToLive(Duration.ofMinutes(2)).reuseRefreshTokens(false).build())
                .redirectUris(uris -> uris.addAll(redirectUris))
                .scopes(scopes -> scopes.addAll(List.of(
                        OidcScopes.OPENID, OidcScopes.PROFILE, OidcScopes.EMAIL, SCOPE_OFFLINE_ACCESS
                )))
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(false).build())
                .build();
    }

    private static RegisteredClient getDemoClientCredentials(PasswordEncoder passwordEncoder) {
        return
                RegisteredClient.withId(UUID.randomUUID().toString())
                        .clientId(CLIENT_ID_DEMO_CLIENT_CREDENTIALS)
                        .clientSecret(passwordEncoder.encode(CLIENT_SECRET_DEMO_CLIENT_CREDENTIALS))
                        .clientAuthenticationMethods(methods -> methods.addAll(
                                List.of(
                                        ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
                                        ClientAuthenticationMethod.CLIENT_SECRET_POST
                                )))
                        .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                        .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                        .tokenSettings(TokenSettings.builder().accessTokenFormat(SELF_CONTAINED)
                                .accessTokenTimeToLive(Duration.ofMinutes(15))
                                .authorizationCodeTimeToLive(Duration.ofMinutes(2)).reuseRefreshTokens(false).build())
                        .scopes(scopes -> scopes.addAll(List.of(
                                OidcScopes.OPENID, OidcScopes.PROFILE, OidcScopes.EMAIL, SCOPE_OFFLINE_ACCESS
                        )))
                        .clientSettings(ClientSettings.builder().requireAuthorizationConsent(false).build())
                        .build();
    }

}
