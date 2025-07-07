package com.example.spring.authorizationserver.config;

import com.example.spring.authorizationserver.security.OidcUserInfoService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

import java.util.List;

import static org.springframework.security.oauth2.server.authorization.OAuth2TokenType.ACCESS_TOKEN;

@Configuration
public class JwtTokenCustomizerConfig {

    public static final String RFC_9068_AT_JWT_TYPE = "at+jwt";
    public static final String JWT_TYPE = "jwt";

    private static final OAuth2TokenType ID_TOKEN = new OAuth2TokenType("id_token");

    private static final Logger LOGGER = LoggerFactory.getLogger(JwtTokenCustomizerConfig.class);

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer(OidcUserInfoService userInfoService) {
        return (context) -> {
            LOGGER.info("tokenExchangeTokenCustomizer, context={}", context);

            if (AuthorizationGrantType.CLIENT_CREDENTIALS.equals(context.getAuthorizationGrantType())) {
                clientCredentialsTokenCustomizer(context);
            } else if (AuthorizationGrantType.TOKEN_EXCHANGE.equals(context.getAuthorizationGrantType())) {
                tokenExchangeTokenCustomizer(context, userInfoService);
            } else {
                authorizationCodeTokenCustomizer(context, userInfoService);
            }
        };
    }

    private void authorizationCodeTokenCustomizer(JwtEncodingContext context, OidcUserInfoService userInfoService) {
        setTokenTypeHeader(context);
        OidcUserInfo userInfo = userInfoService.loadUser(
                context.getPrincipal().getName());
        context.getClaims().claims(claims ->
                claims.putAll(userInfo.getClaims()));
        context.getClaims().claim("client_id", context.getRegisteredClient().getClientId());
    }

    private void clientCredentialsTokenCustomizer(JwtEncodingContext context) {
        setTokenTypeHeader(context);
    }

    private void tokenExchangeTokenCustomizer(JwtEncodingContext context, OidcUserInfoService userInfoService) {
        setTokenTypeHeader(context);
        if (ACCESS_TOKEN.equals(context.getTokenType())) {
             context.getClaims().audience(
                    List.of(
                        "http://localhost:9092/api/messages"
                    )
            );
            context.getClaims().claim("client_id", context.getRegisteredClient().getClientId());
        }
        OidcUserInfo userInfo = userInfoService.loadUser(
                context.getPrincipal().getName());
        context.getClaims().claims(claims ->
                claims.putAll(userInfo.getClaims()));
    }

    private void setTokenTypeHeader(JwtEncodingContext context) {
        if (ACCESS_TOKEN.equals(context.getTokenType())) {
            context.getJwsHeader().type(RFC_9068_AT_JWT_TYPE);
        } else if (ID_TOKEN.equals(context.getTokenType())) {
            context.getJwsHeader().type(JWT_TYPE);
        } else {
            // Nothing to set
            LOGGER.info("Unrecognized token type: {}", context.getTokenType());
        }
    }
}
