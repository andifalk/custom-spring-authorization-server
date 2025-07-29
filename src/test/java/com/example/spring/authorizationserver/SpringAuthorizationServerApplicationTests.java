package com.example.spring.authorizationserver;

import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.web.client.RestClient;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class SpringAuthorizationServerApplicationTests {

    private static final Logger LOGGER = LoggerFactory.getLogger(SpringAuthorizationServerApplicationTests.class);

    @LocalServerPort
    private int port;

    private final RestClient restClient;

    public SpringAuthorizationServerApplicationTests() {
        this.restClient = RestClient.builder().build();
    }

    @Test
    void verifyOpenIDConfiguration() {
        String result = restClient
                .get()
                .uri("http://localhost:" + port + "/.well-known/openid-configuration")
                .header("Accept", "application/json")
                .retrieve()
                .body(String.class);
        assertThat(result).isNotNull().contains("\"issuer\":\"http://localhost:" + port + "\"");
    };

    @Test
    void verifyClientCredentials() {
        String result = restClient
                .post()
                .uri("http://localhost:" + port + "/oauth2/token")
                .header("Accept", "application/json")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .header(HttpHeaders.AUTHORIZATION, "Basic " +
                        Base64.getEncoder().encodeToString(
                                "demo-client-credentials:demo-client-credentials-secret".getBytes(StandardCharsets.UTF_8))
                )
                .body("grant_type=client_credentials")
                .retrieve()
                .body(String.class);
        LOGGER.info("Client credentials {}", result);
        assertThat(result).isNotNull().contains("access_token");
    };
}
