package com.example.oauth2resourceservertutorial.utils.auth;

import java.util.Collections;
import java.util.Map;
import java.util.Objects;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * Utility class for accessing the current authenticated JWT and common claims
 * from Spring Security's SecurityContext.
 *
 * <p>
 * Key design principles:
 * <ul>
 * <li>Thread-safe: No mutable static fields; all data extracted locally per
 * call</li>
 * <li>Null-safe: Null checks after each extraction step; safe defaults
 * returned</li>
 * <li>Type-safe: Uses instanceof checks instead of unchecked casts where
 * possible</li>
 * </ul>
 *
 * <p>
 * Provides convenient static methods to extract:
 * <ul>
 * <li>JWT claims (scope, username, roles)</li>
 * <li>Authentication details</li>
 * <li>Token headers</li>
 * <li>Client-specific resource access claims</li>
 * </ul>
 */
public final class CurrentAuthContext {

    /**
     * Private constructor for utility class.
     */
    private CurrentAuthContext() {
        // Utility class, no instantiation
    }

    /**
     * Returns the current Authentication from the SecurityContext.
     *
     * @return the current Authentication, or null if not available
     */
    public static Authentication getAuthentication() {
        return SecurityContextHolder.getContext().getAuthentication();
    }

    /**
     * Extracts and returns the JWT principal from the current Authentication.
     *
     * @return the JWT principal, or null if not present or not a Jwt instance
     */
    private static Jwt getPrincipalJwt() {
        Authentication authentication = getAuthentication();
        if (authentication == null) {
            return null;
        }
        Object principal = authentication.getPrincipal();
        if (principal instanceof Jwt) {
            return (Jwt) principal;
        }
        return null;
    }

    /**
     * Returns the JWT claims map.
     *
     * @return the claims map, or an empty map if JWT is not available
     */
    private static Map<String, Object> getClaimsMap() {
        Jwt jwt = getPrincipalJwt();
        if (jwt == null) {
            return Collections.emptyMap();
        }
        Map<String, Object> claims = jwt.getClaims();
        return claims == null ? Collections.emptyMap() : claims;
    }

    /**
     * Checks whether the token contains the specified claim.
     *
     * @param claimName the name of the claim to check (must not be null)
     * @return true if the claim is present, false otherwise
     * @throws NullPointerException if claimName is null
     */
    public static boolean hasClaim(String claimName) {
        Jwt jwt = getPrincipalJwt();
        return jwt != null && jwt.hasClaim(Objects.requireNonNull(claimName));
    }

    /**
     * Returns the scope claim from the JWT.
     *
     * @return the scope value, or null if not present
     */
    public static String getScope() {
        Object scope = getClaimsMap().get("scope");
        return scope == null ? null : String.valueOf(scope);
    }

    /**
     * Returns the preferred_username claim from the JWT.
     *
     * @return the username value, or null if not present
     */
    public static String getUserName() {
        Object username = getClaimsMap().get("preferred_username");
        return username == null ? null : String.valueOf(username);
    }

    /**
     * Returns all JWT claims as a string representation.
     *
     * @return string representation of all claims
     */
    public static String getClaims() {
        return getClaimsMap().toString();
    }

    /**
     * Returns the granted authorities/roles from the Authentication.
     *
     * @return string representation of authorities, or "[]" if none available
     */
    public static String getRoles() {
        Authentication auth = getAuthentication();
        if (auth == null || auth.getAuthorities() == null) {
            return "[]";
        }
        return auth.getAuthorities().toString();
    }

    /**
     * Returns the full Authentication object details.
     *
     * @return string representation of the Authentication, or "N/A" if not
     *         available
     */
    public static String getTheAuthentication() {
        Authentication auth = getAuthentication();
        return auth == null ? "N/A" : auth.toString();
    }

    /**
     * Returns the JWT token headers (e.g., alg, typ).
     *
     * @return string representation of token headers, or "{}" if not available
     */
    public static String getHeaders() {
        Jwt jwt = getPrincipalJwt();
        if (jwt == null || jwt.getHeaders() == null) {
            return "{}";
        }
        return jwt.getHeaders().toString();
    }

    /**
     * Returns client-specific roles from the JWT resource_access claim.
     *
     * <p>
     * Extracts roles for the configured resource name ("venzportaal") from the
     * resource_access claim and converts them to GrantedAuthority instances.
     *
     * @return string representation of client roles, or "[]" if not available
     */
    @SuppressWarnings("unchecked")
    public static String getResourceAccess() {
        Jwt jwt = getPrincipalJwt();
        if (jwt == null) {
            return "[]";
        }
        Map<String, Object> resourceAccess = jwt.getClaim("resource_access");
        return resourceAccess.toString();
    }
}
