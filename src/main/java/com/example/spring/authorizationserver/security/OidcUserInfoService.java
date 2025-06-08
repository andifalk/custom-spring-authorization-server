package com.example.spring.authorizationserver.security;

import com.example.spring.authorizationserver.user.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;

public class OidcUserInfoService {
    private static final Logger LOGGER = LoggerFactory.getLogger(OidcUserInfoService.class);

    private final UserDetailsService userDetailsService;

    public OidcUserInfoService(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    public OidcUserInfo loadUser(String username) {
        LOGGER.info("Loading user {}", username);
        User user = (User) userDetailsService.loadUserByUsername(username);
        LOGGER.info("Loaded user {}", user);
        return OidcUserInfo.builder()
                .subject(user.getIdentifier().toString())
                .name(user.getFirstName() + " " + user.getLastName())
                .givenName(user.getFirstName())
                .familyName(user.getLastName())
                .nickname(username)
                .preferredUsername(username)
                .profile("https://example.com/" + username)
                .website("https://example.com")
                .email(user.getEmail())
                .emailVerified(true)
                .claim("roles", user.getRoles())
                .zoneinfo("Europe/Berlin")
                .locale("de-DE")
                .updatedAt("1970-01-01T00:00:00Z")
                .build();
    }
}
