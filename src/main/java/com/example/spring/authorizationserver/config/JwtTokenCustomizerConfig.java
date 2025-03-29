package com.example.spring.authorizationserver.config;

import com.example.spring.authorizationserver.security.OidcUserInfoService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

import java.util.List;

import static org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames.ID_TOKEN;
import static org.springframework.security.oauth2.server.authorization.OAuth2TokenType.ACCESS_TOKEN;

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
                        if (!AuthorizationGrantType.TOKEN_EXCHANGE.equals(context.getAuthorizationGrantType())) {
                            context.getClaims().audience(
                                    List.of(
                                            context.getRegisteredClient().getClientId(),
                                            "demo-api"
                                    )
                            );
                        }
                    }
                }
            }
        };
    }
}
