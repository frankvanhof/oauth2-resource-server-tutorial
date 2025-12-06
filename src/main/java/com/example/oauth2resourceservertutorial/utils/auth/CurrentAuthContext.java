package com.example.oauth2resourceservertutorial.utils.auth;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.List;
import java.util.Map;

public class CurrentAuthContext {
    public static final String extractClaim = null;
    private static Jwt principal;

    private static Authentication extractAuthentication() {
        return SecurityContextHolder.getContext().getAuthentication();
    }

    private static Map<String, Object> extractClaim() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Object principal = authentication.getPrincipal();

        Map<String, Object> claims = ((Jwt) principal).getClaims();
        return claims;
    }

    private static Jwt extractPrincipal() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Jwt principal = (Jwt) authentication.getPrincipal();

        return principal;
    }

    public static String hasClaim() {
        principal = extractPrincipal();
        return String.valueOf(principal.hasClaim("bevolken-api"));
    }

    public static String getScope() {
        return (String) extractClaim().get("scope");
    }

    public static String getUserEmail() {
        return (String) extractClaim().get("email");
    }

    public static String getClaims() {
        return extractClaim().toString();
    }

    public static String getRoles() {
        return extractAuthentication().getAuthorities().toString();
    }

    public static String getAuthentication() {
        return extractAuthentication().toString();
    }

    public static String getHeaders() {
        principal = extractPrincipal();

        return principal.getHeaders().toString();
    }

        public static String getResourceAccess() {
            principal = extractPrincipal();
    
            Map<String, Object> raccess = (Map<String, Object>) principal.getClaims().get("realm_access");
            List<String> roles = (List<String>) raccess.get("roles");
            return roles.toString();
        }
    }