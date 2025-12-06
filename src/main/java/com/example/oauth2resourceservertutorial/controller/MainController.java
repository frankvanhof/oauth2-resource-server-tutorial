package com.example.oauth2resourceservertutorial.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.oauth2resourceservertutorial.utils.auth.CurrentAuthContext;

import java.util.Map;
import java.util.Optional;

@RestController
public class MainController {

    @GetMapping("/public")
    public ResponseEntity<String> homePage() {
        return ResponseEntity.ok("Hello from Spring boot app");
    }

    @GetMapping("/private")
    public ResponseEntity<Map<String, Object>> privateRoute() {
        // Return a small, explicit subset of claims rather than everything
        return ResponseEntity.ok(Map.of(
                "username", Optional.ofNullable(CurrentAuthContext.getUserName()).orElse("anonymous"),
                "scope", Optional.ofNullable(CurrentAuthContext.getScope()).orElse(""),
                "roles", CurrentAuthContext.getResourceAccess()));
    }

    @GetMapping("/claims")
    public ResponseEntity<String> claimsRoute() {
        return CurrentAuthContext.getClaims().isEmpty()
                ? ResponseEntity.noContent().build()
                : ResponseEntity.ok(CurrentAuthContext.getClaims());
    }

    @GetMapping("/scope")
    public ResponseEntity<String> scopeRoute() {
        return Optional.ofNullable(CurrentAuthContext.getScope())
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.noContent().build());
    }

    @GetMapping("/username")
    public ResponseEntity<String> usernameRoute() {
        return Optional.ofNullable(CurrentAuthContext.getUserName())
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.noContent().build());
    }

    @GetMapping("/roles")
    public ResponseEntity<String> rolesRoute() {
        return ResponseEntity.ok(CurrentAuthContext.getRoles());
    }

    @GetMapping("/authentication")
    public ResponseEntity<String> authenticationRoute() {
        return ResponseEntity.ok(CurrentAuthContext.getAuthentication().toString());
    }

    @GetMapping("/headers")
    public ResponseEntity<String> headersRoute() {
        // Consider removing or protecting this endpoint in production
        return ResponseEntity.ok(CurrentAuthContext.getHeaders());
    }

    @GetMapping("/resourceaccess")
    public ResponseEntity<String> resourceAccessRoute() {
        return ResponseEntity.ok(CurrentAuthContext.getResourceAccess());
    }
}
