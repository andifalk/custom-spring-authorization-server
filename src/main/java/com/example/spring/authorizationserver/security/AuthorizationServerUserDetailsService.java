package com.example.spring.authorizationserver.security;

import com.example.spring.authorizationserver.user.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import java.util.*;

@Service
public class AuthorizationServerUserDetailsService implements UserDetailsService {

    private final PasswordEncoder passwordEncoder;
    private final Map<String, User> users = new HashMap();

    public AuthorizationServerUserDetailsService(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @PostConstruct
    public void initUsers() {
        Set<String> bwayneRoles = new HashSet<>();
        bwayneRoles.add("USER");
        User bwayne = new User(UUID.randomUUID(), "bwayne", passwordEncoder.encode("wayne"),
                "Bruce", "Wayne", "bruce.wayne@example.com", bwayneRoles);
        Set<String> ckentRoles = new HashSet<>();
        ckentRoles.add("USER");
        ckentRoles.add("ADMIN");
        User ckent = new User(UUID.randomUUID(), "ckent", passwordEncoder.encode("kent"),
                "Clark", "Kent", "clark.kent@example.com", ckentRoles);
        users.put("bwayne", bwayne);
        users.put("ckent", ckent);
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        if (users.containsKey(username)) {
            return users.get(username);
        } else {
            throw new UsernameNotFoundException("No user found for " + username);
        }
    }
}
