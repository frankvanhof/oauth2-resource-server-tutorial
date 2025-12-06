package com.example.oauth2resourceservertutorial;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;

/**
 * Main Spring Boot application entry point for the OAuth2 Resource Server.
 * 
 * Excludes SecurityAutoConfiguration to allow for manual SecurityFilterChain configuration
 * via {@link com.example.oauth2resourceservertutorial.config.SecurityConfig}.
 */
@SpringBootApplication(exclude = {SecurityAutoConfiguration.class})
public class Oauth2ResourceServerTutorialApplication {

    /**
     * Main method to start the Spring Boot application.
     *
     * @param args command line arguments
     */
    public static void main(String[] args) {
        SpringApplication.run(Oauth2ResourceServerTutorialApplication.class, args);
    }
}