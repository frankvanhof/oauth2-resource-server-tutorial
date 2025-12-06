package com.example.oauth2resourceservertutorial.controller;

import java.util.Map;
import java.util.Optional;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.oauth2resourceservertutorial.utils.auth.CurrentAuthContext;

/**
 * REST controller exposing endpoints for testing OAuth2 authentication and JWT claims extraction.
 */
@RestController
public class MainController {

    /**
     * Public endpoint accessible without authentication.
     *
     * @return greeting message
     */
    @GetMapping("/public")
    public ResponseEntity<String> homePage() {
        return ResponseEntity.ok("Hello from Spring boot app");
    }

    /**
     * Protected endpoint returning authenticated user's claims.
     *
     * @return map containing username, scope, and roles
     */
    @GetMapping("/private")
    public ResponseEntity<Map<String, Object>> privateRoute() {
        return ResponseEntity.ok(Map.of(
            "username", Optional.ofNullable(CurrentAuthContext.getUserName()).orElse("anonymous"),
            "scope", Optional.ofNullable(CurrentAuthContext.getScope()).orElse(""),
            "roles", CurrentAuthContext.getResourceAccess()
        ));
    }

    /**
     * Returns all JWT claims as a string representation.
     *
     * @return JWT claims or 204 No Content if no claims available
     */
    @GetMapping("/claims")
    public ResponseEntity<String> claimsRoute() {
        return CurrentAuthContext.getClaims().isEmpty()
            ? ResponseEntity.noContent().build()
            : ResponseEntity.ok(CurrentAuthContext.getClaims());
    }

    /**
     * Returns the scope claim from the JWT token.
     *
     * @return scope string or 204 No Content if not available
     */
    @GetMapping("/scope")
    public ResponseEntity<String> scopeRoute() {
        return Optional.ofNullable(CurrentAuthContext.getScope())
            .map(ResponseEntity::ok)
            .orElseGet(() -> ResponseEntity.noContent().build());
    }

    /**
     * Returns the preferred_username claim from the JWT token.
     *
     * @return username or 204 No Content if not available
     */
    @GetMapping("/username")
    public ResponseEntity<String> usernameRoute() {
        return Optional.ofNullable(CurrentAuthContext.getUserName())
            .map(ResponseEntity::ok)
            .orElseGet(() -> ResponseEntity.noContent().build());
    }

    /**
     * Returns the granted authorities/roles.
     *
     * @return roles as string representation
     */
    @GetMapping("/roles")
    public ResponseEntity<String> rolesRoute() {
        return ResponseEntity.ok(CurrentAuthContext.getRoles());
    }

    /**
     * Returns the full Authentication object details.
     *
     * @return authentication details
     */
    @GetMapping("/authentication")
    public ResponseEntity<String> authenticationRoute() {
        return ResponseEntity.ok(CurrentAuthContext.getAuthentication().toString());
    }

    /**
     * Returns JWT token headers (e.g., alg, typ).
     * 
     * Note: Consider removing or protecting this endpoint in production.
     *
     * @return token headers as string representation
     */
    @GetMapping("/headers")
    public ResponseEntity<String> headersRoute() {
        return ResponseEntity.ok(CurrentAuthContext.getHeaders());
    }

    /**
     * Returns client-specific roles from the JWT resource_access claim.
     *
     * @return client roles as string representation
     */
    @GetMapping("/resourceaccess")
    public ResponseEntity<String> resourceAccessRoute() {
        return ResponseEntity.ok(CurrentAuthContext.getResourceAccess());
    }
}
