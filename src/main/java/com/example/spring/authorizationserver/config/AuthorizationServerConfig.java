package com.example.spring.authorizationserver.config;

import com.example.spring.authorizationserver.jose.Jwks;
import com.example.spring.authorizationserver.user.User;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabase;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2TokenFormat;
import org.springframework.security.oauth2.core.OAuth2TokenType;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.config.TokenSettings;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

@Configuration(proxyBeanMethods = false)
public class AuthorizationServerConfig {

    private static final Logger LOGGER = LoggerFactory.getLogger(AuthorizationServerConfig.class);

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain h2ConsoleSecurityFilterChain(HttpSecurity http) throws Exception {
        http.requestMatcher(PathRequest.toH2Console())
                .csrf().disable()
                .headers().frameOptions().disable()
                .and()
                .authorizeRequests().anyRequest().permitAll();
        return http.build();
    }

    /*
     * Security config for all authz server endpoints.
     */
    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE + 1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {

        OAuth2AuthorizationServerConfigurer<HttpSecurity> authorizationServerConfigurer =
                new OAuth2AuthorizationServerConfigurer<>();
        RequestMatcher endpointsMatcher = authorizationServerConfigurer
                .getEndpointsMatcher();

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

        http
                .requestMatcher(endpointsMatcher)
                .authorizeRequests(authorizeRequests ->
                        authorizeRequests.anyRequest().authenticated()
                )
                .csrf(csrf -> csrf.ignoringRequestMatchers(endpointsMatcher))
                .apply(authorizationServerConfigurer);
        http.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);
        return http.formLogin(Customizer.withDefaults()).build();
    }

    /*
     * Repository with all registered OAuth/OIDC clients.
     */
    @Bean
    public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate, PasswordEncoder passwordEncoder) {
        RegisteredClient demoClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("demo-client")
                .clientSecret(passwordEncoder.encode("secret"))
                .clientAuthenticationMethods(methods -> methods.addAll(
                        List.of(
                                ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
                                ClientAuthenticationMethod.CLIENT_SECRET_POST
                        )))
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .redirectUri("http://127.0.0.1:9095/client/callback")
                .redirectUri("http://127.0.0.1:9095/client/authorized")
                .redirectUri("http://127.0.0.1:9095/client")
                .redirectUri("http://127.0.0.1:9095/login/oauth2/code/spring-authz-server")
                .redirectUri("https://oauth.pstmn.io/v1/callback")
                .scopes(scopes -> scopes.addAll(List.of(
                        OidcScopes.OPENID, OidcScopes.PROFILE, OidcScopes.EMAIL, "offline_access"
                )))
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(false).build())
                .build();

        RegisteredClient demoClientPkce = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("demo-client-pkce")
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .redirectUri("http://127.0.0.1:9095/client/callback")
                .redirectUri("http://127.0.0.1:9095/client/authorized")
                .redirectUri("http://127.0.0.1:9095/client")
                .redirectUri("http://127.0.0.1:9095/login/oauth2/code/spring-authz-server")
                .redirectUri("https://oauth.pstmn.io/v1/callback")
                .scopes(scopes -> scopes.addAll(List.of(
                        OidcScopes.OPENID, OidcScopes.PROFILE, OidcScopes.EMAIL, "offline_access"
                )))
                .clientSettings(ClientSettings.builder().requireProofKey(true).requireAuthorizationConsent(false).build())
                .build();

        RegisteredClient demoClientOpaque = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("demo-client-opaque")
                .clientSecret(passwordEncoder.encode("secret"))
                .clientAuthenticationMethods(methods -> methods.addAll(
                        List.of(
                                ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
                                ClientAuthenticationMethod.CLIENT_SECRET_POST
                        )))
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .tokenSettings(TokenSettings.builder().accessTokenFormat(OAuth2TokenFormat.REFERENCE).build())
                .redirectUri("http://127.0.0.1:9095/client/callback")
                .redirectUri("http://127.0.0.1:9095/client/authorized")
                .redirectUri("http://127.0.0.1:9095/client")
                .redirectUri("http://127.0.0.1:9095/login/oauth2/code/spring-authz-server")
                .redirectUri("https://oauth.pstmn.io/v1/callback")
                .scopes(scopes -> scopes.addAll(List.of(
                        OidcScopes.OPENID, OidcScopes.PROFILE, OidcScopes.EMAIL, "offline_access"
                )))
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(false).build())
                .build();

        RegisteredClient demoClientPkceOpaque = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("demo-client-pkce-opaque")
                .clientSecret(passwordEncoder.encode("secret"))
                .clientAuthenticationMethods(methods -> methods.addAll(
                        List.of(
                                ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
                                ClientAuthenticationMethod.CLIENT_SECRET_POST,
                                ClientAuthenticationMethod.NONE
                        )))
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .tokenSettings(TokenSettings.builder().accessTokenFormat(OAuth2TokenFormat.REFERENCE).build())
                .redirectUri("http://127.0.0.1:9095/client/callback")
                .redirectUri("http://127.0.0.1:9095/client/authorized")
                .redirectUri("http://127.0.0.1:9095/client")
                .redirectUri("http://127.0.0.1:9095/login/oauth2/code/spring-authz-server")
                .redirectUri("https://oauth.pstmn.io/v1/callback")
                .scopes(scopes -> scopes.addAll(List.of(
                        OidcScopes.OPENID, OidcScopes.PROFILE, OidcScopes.EMAIL, "offline_access"
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

    /*
     * Generate the private/public key pair for signature of JWT.
     */
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        RSAKey rsaKey = Jwks.generateRsa();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
    }

    @Bean
    public ProviderSettings providerSettings() {
        return ProviderSettings.builder().issuer("http://localhost:9000").build();
    }

    @Bean
    public EmbeddedDatabase embeddedDatabase() {
        // @formatter:off
        return new EmbeddedDatabaseBuilder()
                .generateUniqueName(false)
                .setName("authzserver")
                .setType(EmbeddedDatabaseType.H2)
                .setScriptEncoding("UTF-8")
                .addScript("org/springframework/security/oauth2/server/authorization/oauth2-authorization-schema.sql")
                .addScript("org/springframework/security/oauth2/server/authorization/oauth2-authorization-consent-schema.sql")
                .addScript("org/springframework/security/oauth2/server/authorization/client/oauth2-registered-client-schema.sql")
                .build();
        // @formatter:on
    }

    /*
     * Customizes token contents for this authz server.
     */
    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer() {
        return context -> {
            UsernamePasswordAuthenticationToken authentication = context.getPrincipal();
            LOGGER.info("Customizing {} for user {}", context.getTokenType(), authentication.getPrincipal());
            if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
                context.getHeaders().header("typ", "jwt");
                context.getClaims().claims(m -> {
                    Set<String> existingScopes = (Set<String>) m.get("scope");
                    Set<String> additional = ((User) authentication.getPrincipal()).getRoles();
                    additional.addAll(existingScopes);
                    m.replace("scope", additional);
                });
                context.getClaims().subject(((User) authentication.getPrincipal()).getIdentifier().toString());
                context.getClaims().claim("roles", ((User) authentication.getPrincipal()).getRoles());
                context.getClaims().claim("scp", ((User) authentication.getPrincipal()).getRoles());
                context.getClaims().claim("given_name", ((User) authentication.getPrincipal()).getFirstName());
                context.getClaims().claim("family_name", ((User) authentication.getPrincipal()).getLastName());
                context.getClaims().claim("email", ((User) authentication.getPrincipal()).getEmail());
            } else if (OAuth2TokenType.REFRESH_TOKEN.equals(context.getTokenType())) {
                // Nothing to do here
            } else {
                context.getHeaders().header("typ", "jwt");
                context.getClaims().subject(((User) authentication.getPrincipal()).getIdentifier().toString());
                context.getClaims().claim("roles", ((User) authentication.getPrincipal()).getRoles());
                context.getClaims().claim("scp", ((User) authentication.getPrincipal()).getRoles());
                context.getClaims().claim("given_name", ((User) authentication.getPrincipal()).getFirstName());
                context.getClaims().claim("family_name", ((User) authentication.getPrincipal()).getLastName());
                context.getClaims().claim("email", ((User) authentication.getPrincipal()).getEmail());
            }
        };
    }
}
