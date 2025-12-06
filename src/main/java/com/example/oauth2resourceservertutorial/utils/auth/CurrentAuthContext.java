package com.example.oauth2resourceservertutorial.utils.auth;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Utility helpers to access the current authenticated JWT and common claims.
 *
 * Improvements made:
 * - Removed mutable static fields to avoid thread-safety issues.
 * - Added null checks to avoid NPEs when no authentication is present.
 * - Avoided unchecked casts where possible and returned safe defaults.
 */
public final class CurrentAuthContext {
    private CurrentAuthContext() {
        // utility class
    }

    public static Authentication getAuthentication() {
        return SecurityContextHolder.getContext().getAuthentication();
    }

    private static Jwt getPrincipalJwt() {
        Authentication authentication = getAuthentication();
        if (authentication == null)
            return null;
        Object principal = authentication.getPrincipal();
        if (principal instanceof Jwt)
            return (Jwt) principal;
        return null;
    }

    private static Map<String, Object> getClaimsMap() {
        Jwt jwt = getPrincipalJwt();
        if (jwt == null)
            return Collections.emptyMap();
        Map<String, Object> claims = jwt.getClaims();
        return claims == null ? Collections.emptyMap() : claims;
    }

    /**
     * Checks whether the token contains the named claim.
     *
     * @param claimName claim to check
     * @return true if present, false otherwise
     */
    public static boolean hasClaim(String claimName) {
        Jwt jwt = getPrincipalJwt();
        return jwt != null && jwt.hasClaim(Objects.requireNonNull(claimName));
    }

    public static String getScope() {
        Object s = getClaimsMap().get("scope");
        return s == null ? null : String.valueOf(s);
    }

    public static String getUserName() {
        Object u = getClaimsMap().get("preferred_username");
        return u == null ? null : String.valueOf(u);
    }

    public static String getClaims() {
        return getClaimsMap().toString();
    }

    public static String getRoles() {
        Authentication auth = getAuthentication();
        if (auth == null || auth.getAuthorities() == null)
            return "[]";
        return auth.getAuthorities().toString();
    }

    public static String getTheAuthentication() {
        Authentication auth = getAuthentication();
        return auth == null ? "N/A" : auth.toString();
    }

    public static String getHeaders() {
        Jwt jwt = getPrincipalJwt();
        if (jwt == null || jwt.getHeaders() == null)
            return "{}";
        return jwt.getHeaders().toString();
    }

    @SuppressWarnings("unchecked")
    public static String getResourceAccess() {
        final String resourceName="venzportaal";
        Collection<GrantedAuthority> resourceAuthorities = new ArrayList<>();
        
        Jwt jwt = getPrincipalJwt();
        if (jwt == null)
            return "[]";
        // 2. Collect Client Roles (venzportaal)
        Map<String, Object> resourceAccess = jwt.getClaim("resource_access");
        if (resourceAccess != null && resourceAccess.containsKey(resourceName)) {
            Map<String, Object> clientRoles = (Map<String, Object>) resourceAccess.get(resourceName);
            if (clientRoles.containsKey("roles")) {
                List<String> roles = (List<String>) clientRoles.get("roles");
                roles.forEach(roleName -> resourceAuthorities.add(new SimpleGrantedAuthority(roleName)));
            }
        }
        return resourceAuthorities.toString();
    }
}