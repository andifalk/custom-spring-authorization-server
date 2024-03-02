package com.example.spring.authorizationserver.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
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
    private static final String SCOPE_OFFLINE_ACCESS = "offline_access";
    private static final String CLIENT_SECRET = "secret";

    /*
     * Repository with all registered OAuth/OIDC clients.
     */
    @Bean
    public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate, PasswordEncoder passwordEncoder) {
        Set<String> redirectUris = getRedirectUris();

        RegisteredClient demoClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("demo-client")
                .clientSecret(passwordEncoder.encode(CLIENT_SECRET))
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
                        .authorizationCodeTimeToLive(Duration.ofMinutes(2)).build())
                .redirectUris(uris -> uris.addAll(redirectUris))
                .scopes(scopes -> scopes.addAll(List.of(
                        OidcScopes.OPENID, OidcScopes.PROFILE, OidcScopes.EMAIL, SCOPE_OFFLINE_ACCESS
                )))
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(false).build())
                .build();

        RegisteredClient demoClientPkce = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("demo-client-pkce")
                .clientAuthenticationMethods(methods -> methods.add(
                        ClientAuthenticationMethod.NONE
                ))
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .tokenSettings(TokenSettings.builder().accessTokenFormat(SELF_CONTAINED)
                        .accessTokenTimeToLive(Duration.ofMinutes(15))
                        .authorizationCodeTimeToLive(Duration.ofMinutes(2)).build())
                .redirectUris(uris -> uris.addAll(redirectUris))
                .scopes(scopes -> scopes.addAll(List.of(
                        OidcScopes.OPENID, OidcScopes.PROFILE, OidcScopes.EMAIL, SCOPE_OFFLINE_ACCESS
                )))
                .clientSettings(ClientSettings.builder().requireProofKey(true).requireAuthorizationConsent(false).build())
                .build();

        RegisteredClient demoClientOpaque = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("demo-client-opaque")
                .clientSecret(passwordEncoder.encode(CLIENT_SECRET))
                .clientAuthenticationMethods(methods -> methods.addAll(
                        List.of(
                                ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
                                ClientAuthenticationMethod.CLIENT_SECRET_POST
                        )))
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .tokenSettings(TokenSettings.builder().accessTokenFormat(OAuth2TokenFormat.REFERENCE)
                        .accessTokenTimeToLive(Duration.ofMinutes(15))
                        .authorizationCodeTimeToLive(Duration.ofMinutes(2)).build())
                .redirectUris(uris -> uris.addAll(redirectUris))
                .scopes(scopes -> scopes.addAll(List.of(
                        OidcScopes.OPENID, OidcScopes.PROFILE, OidcScopes.EMAIL, SCOPE_OFFLINE_ACCESS
                )))
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(false).build())
                .build();

        RegisteredClient demoClientPkceOpaque = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("demo-client-pkce-opaque")
                .clientAuthenticationMethods(methods -> methods.add(
                        ClientAuthenticationMethod.NONE
                ))
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .tokenSettings(TokenSettings.builder().accessTokenFormat(OAuth2TokenFormat.REFERENCE)
                        .accessTokenTimeToLive(Duration.ofMinutes(15))
                        .authorizationCodeTimeToLive(Duration.ofMinutes(2)).build())
                .redirectUris(uris -> {
                    uris.addAll(redirectUris);
                })
                .scopes(scopes -> scopes.addAll(List.of(
                        OidcScopes.OPENID, OidcScopes.PROFILE, OidcScopes.EMAIL, SCOPE_OFFLINE_ACCESS
                )))
                .clientSettings(ClientSettings.builder().requireProofKey(true).requireAuthorizationConsent(false).build())
                .build();

        // Save registered client in db as if in-memory
        JdbcRegisteredClientRepository registeredClientRepository = new JdbcRegisteredClientRepository(jdbcTemplate);
        registeredClientRepository.save(demoClient);
        registeredClientRepository.save(demoClientPkce);
        registeredClientRepository.save(demoClientOpaque);
        registeredClientRepository.save(demoClientPkceOpaque);

        LOGGER.info("Registered OAuth2/OIDC clients");

        return registeredClientRepository;
    }

    @Bean
    public OAuth2AuthorizationService authorizationService(JdbcTemplate jdbcTemplate, RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository);
    }

    @Bean
    public OAuth2AuthorizationConsentService authorizationConsentService(JdbcTemplate jdbcTemplate, RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationConsentService(jdbcTemplate, registeredClientRepository);
    }

    private static Set<String> getRedirectUris() {
        Set<String> redirectUris = new HashSet<>();
        redirectUris.add("http://127.0.0.1:9095/client/callback");
        redirectUris.add("http://127.0.0.1:9095/client");
        redirectUris.add("http://127.0.0.1:9090/login/oauth2/code/spring");
        redirectUris.add("http://127.0.0.1:9095/client/login/oauth2/code/spring");
        redirectUris.add("http://localhost:9095/client/callback");
        redirectUris.add("http://localhost:9095/client");
        redirectUris.add("http://localhost:9090/login/oauth2/code/spring");
        redirectUris.add("http://localhost:9095/client/login/oauth2/code/spring");
        redirectUris.add("https://oauth.pstmn.io/v1/callback");
        return redirectUris;
    }

}
