package com.example.spring.authorizationserver.security;

import com.example.spring.authorizationserver.user.User;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.*;

@Service
public class AuthorizationServerUserDetailsService implements UserDetailsService {

    public static final String WAYNE_ID = "c52bf7db-db55-4f89-ac53-82b40e8c57c2";
    public static final String KENT_ID = "52a14872-ba6b-488f-aa4d-453b11f9ddce";
    public static final String PARKER_ID = "3a73ef49-c671-4d66-b6f2-7725ccde5c2b";

    private static final Logger LOGGER = LoggerFactory.getLogger(AuthorizationServerUserDetailsService.class);

    private final PasswordEncoder passwordEncoder;
    private final Map<String, User> users = new HashMap<>();

    public AuthorizationServerUserDetailsService(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @PostConstruct
    public void initUsers() {
        Set<String> bWayneRoles = new HashSet<>();
        bWayneRoles.add("USER");
        User bWayne = new User(UUID.fromString(WAYNE_ID), "bwayne", passwordEncoder.encode("wayne"),
                "Bruce", "Wayne", "bruce.wayne@example.com", bWayneRoles);
        Set<String> cKentRoles = new HashSet<>();
        cKentRoles.add("USER");
        User cKent = new User(UUID.fromString(KENT_ID), "ckent", passwordEncoder.encode("kent"),
                "Clark", "Kent", "clark.kent@example.com", cKentRoles);
        Set<String> pParkerRoles = new HashSet<>();
        pParkerRoles.add("USER");
        pParkerRoles.add("ADMIN");
        User pParker = new User(UUID.fromString(PARKER_ID), "pparker", passwordEncoder.encode("parker"),
                "Peter", "Parker", "peter.parker@example.com", pParkerRoles);
        users.put("bwayne", bWayne);
        users.put("ckent", cKent);
        users.put("pparker", pParker);

        LOGGER.info("Initialized users {}, {} and {}", bWayne, cKent, pParker);
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        if (users.containsKey(username)) {
            LOGGER.info("Found user for {}", username);
            return users.get(username);
        } else {
            LOGGER.warn("No user found for {}", username);
            throw new UsernameNotFoundException("No user found for " + username);
        }
    }
}
