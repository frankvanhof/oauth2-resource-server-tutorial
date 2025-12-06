package com.example.oauth2resourceservertutorial.utils.auth;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link CurrentAuthContext}.
 *
 * Tests cover:
 * - Null/missing authentication scenarios
 * - Valid JWT token with claims
 * - Extraction of specific claims (scope, username, roles, etc.)
 * - Safe handling of missing nested objects
 */
class CurrentAuthContextTest {

    private SecurityContext securityContext;
    private Authentication authentication;
    private Jwt jwt;

    @BeforeEach
    void setUp() {
        securityContext = mock(SecurityContext.class);
        authentication = mock(Authentication.class);
        jwt = createMockJwt();
        SecurityContextHolder.setContext(securityContext);
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    /**
     * Creates a mock JWT with standard OAuth2 claims.
     */
    private Jwt createMockJwt() {
        Map<String, Object> headers = new HashMap<>();
        headers.put("alg", "RS256");
        headers.put("typ", "JWT");

        Map<String, Object> claims = new HashMap<>();
        claims.put("scope", "read:data write:data");
        claims.put("preferred_username", "john.doe");
        claims.put("realm_access", Map.of(
            "roles", Arrays.asList("admin", "user")
        ));
        claims.put("resource_access", Map.of("venzportaal",Map.of(
            "roles", Arrays.asList("bevolken-api", "user"))
        ));

        Jwt mockJwt = mock(Jwt.class);
        when(mockJwt.getHeaders()).thenReturn(headers);
        when(mockJwt.getClaims()).thenReturn(claims);
        when(mockJwt.hasClaim("bevolken-api")).thenReturn(true);
        when(mockJwt.hasClaim("missing-claim")).thenReturn(false);

        return mockJwt;
    }

    // ========== Tests for null/missing authentication ==========

    @Test
    void testHasClaimWhenNoAuthentication() {
        when(securityContext.getAuthentication()).thenReturn(null);
        assertFalse(CurrentAuthContext.hasClaim("any-claim"));
    }

    @Test
    void testHasClaimWhenPrincipalIsNotJwt() {
        when(securityContext.getAuthentication()).thenReturn(authentication);
        when(authentication.getPrincipal()).thenReturn("string-principal");
        assertFalse(CurrentAuthContext.hasClaim("any-claim"));
    }

    @Test
    void testGetScopeWhenNoAuthentication() {
        when(securityContext.getAuthentication()).thenReturn(null);
        assertNull(CurrentAuthContext.getScope());
    }

    @Test
    void testGetUserNameWhenNoAuthentication() {
        when(securityContext.getAuthentication()).thenReturn(null);
        assertNull(CurrentAuthContext.getUserName());
    }

    @Test
    void testGetClaimsWhenNoAuthentication() {
        when(securityContext.getAuthentication()).thenReturn(null);
        assertEquals("{}", CurrentAuthContext.getClaims());
    }

    @Test
    void testGetRolesWhenNoAuthentication() {
        when(securityContext.getAuthentication()).thenReturn(null);
        assertEquals("[]", CurrentAuthContext.getRoles());
    }

    @Test
    void testGetAuthenticationWhenNoAuthentication() {
        when(securityContext.getAuthentication()).thenReturn(null);
        assertEquals("N/A", CurrentAuthContext.getTheAuthentication());
    }

    @Test
    void testGetHeadersWhenNoAuthentication() {
        when(securityContext.getAuthentication()).thenReturn(null);
        assertEquals("{}", CurrentAuthContext.getHeaders());
    }

    @Test
    void testGetResourceAccessWhenNoAuthentication() {
        when(securityContext.getAuthentication()).thenReturn(null);
        assertEquals("[]", CurrentAuthContext.getResourceAccess());
    }

    // ========== Tests for valid JWT with claims ==========

    @Test
    void testHasClaimWithValidJwt() {
        when(securityContext.getAuthentication()).thenReturn(authentication);
        when(authentication.getPrincipal()).thenReturn(jwt);

        assertTrue(CurrentAuthContext.hasClaim("bevolken-api"));
        assertFalse(CurrentAuthContext.hasClaim("missing-claim"));
    }

    @Test
    void testGetScopeWithValidJwt() {
        when(securityContext.getAuthentication()).thenReturn(authentication);
        when(authentication.getPrincipal()).thenReturn(jwt);

        assertEquals("read:data write:data", CurrentAuthContext.getScope());
    }

    @Test
    void testGetUserNameWithValidJwt() {
        when(securityContext.getAuthentication()).thenReturn(authentication);
        when(authentication.getPrincipal()).thenReturn(jwt);

        assertEquals("john.doe", CurrentAuthContext.getUserName());
    }

    @Test
    void testGetClaimsWithValidJwt() {
        when(securityContext.getAuthentication()).thenReturn(authentication);
        when(authentication.getPrincipal()).thenReturn(jwt);

        String claims = CurrentAuthContext.getClaims();
        assertTrue(claims.contains("scope"));
        assertTrue(claims.contains("preferred_username"));
    }

    @Test
    void testGetHeadersWithValidJwt() {
        when(securityContext.getAuthentication()).thenReturn(authentication);
        when(authentication.getPrincipal()).thenReturn(jwt);

        String headers = CurrentAuthContext.getHeaders();
        assertTrue(headers.contains("alg"));
        assertTrue(headers.contains("RS256"));
    }

    @Test
    void testGetResourceAccessWithValidJwt() {
        when(securityContext.getAuthentication()).thenReturn(authentication);
        when(authentication.getPrincipal()).thenReturn(jwt);

        String resourceAccess = CurrentAuthContext.getResourceAccess();
        assertTrue(resourceAccess.contains("bevolken-api"));
        assertTrue(resourceAccess.contains("user"));
    }

    @Test
    void testGetRolesWithValidAuthorities() {
        Collection<? extends GrantedAuthority> authorities = Arrays.asList(
            new SimpleGrantedAuthority("ROLE_ADMIN"),
            new SimpleGrantedAuthority("ROLE_USER")
        );

        when(securityContext.getAuthentication()).thenReturn(authentication);
        when(authentication.getAuthorities()).thenReturn((Collection) authorities);

        String roles = CurrentAuthContext.getRoles();
        assertTrue(roles.contains("ROLE_ADMIN"));
        assertTrue(roles.contains("ROLE_USER"));
    }

    @Test
    void testGetAuthenticationWithValidAuth() {
        when(securityContext.getAuthentication()).thenReturn(authentication);
        when(authentication.toString()).thenReturn("MockAuthentication");

        assertEquals("MockAuthentication", CurrentAuthContext.getAuthentication().toString());
    }

    // ========== Tests for edge cases ==========

    @Test
    void testGetScopeWhenClaimMissing() {
        when(securityContext.getAuthentication()).thenReturn(authentication);
        when(authentication.getPrincipal()).thenReturn(jwt);

        Map<String, Object> claims = new HashMap<>();
        // No "scope" key
        Jwt jwtNoScope = mock(Jwt.class);
        when(jwtNoScope.getClaims()).thenReturn(claims);
        when(authentication.getPrincipal()).thenReturn(jwtNoScope);

        assertNull(CurrentAuthContext.getScope());
    }

    @Test
    void testGetResourceAccessWhenRealmAccessMissing() {
        when(securityContext.getAuthentication()).thenReturn(authentication);

        Map<String, Object> claimsNoRealmAccess = new HashMap<>();
        Jwt jwtNoRealmAccess = mock(Jwt.class);
        when(jwtNoRealmAccess.getClaims()).thenReturn(claimsNoRealmAccess);
        when(authentication.getPrincipal()).thenReturn(jwtNoRealmAccess);

        assertEquals("[]", CurrentAuthContext.getResourceAccess());
    }

    @Test
    void testGetResourceAccessWhenRealmAccessIsNotMap() {
        when(securityContext.getAuthentication()).thenReturn(authentication);

        Map<String, Object> claims = new HashMap<>();
        claims.put("realm_access", "not-a-map");
        Jwt jwtBadRealmAccess = mock(Jwt.class);
        when(jwtBadRealmAccess.getClaims()).thenReturn(claims);
        when(authentication.getPrincipal()).thenReturn(jwtBadRealmAccess);

        assertEquals("[]", CurrentAuthContext.getResourceAccess());
    }

    @Test
    void testGetResourceAccessWhenRolesIsNotList() {
        when(securityContext.getAuthentication()).thenReturn(authentication);

        Map<String, Object> realmAccess = new HashMap<>();
        realmAccess.put("roles", "not-a-list");
        Map<String, Object> claims = new HashMap<>();
        claims.put("realm_access", realmAccess);
        Jwt jwtBadRoles = mock(Jwt.class);
        when(jwtBadRoles.getClaims()).thenReturn(claims);
        when(authentication.getPrincipal()).thenReturn(jwtBadRoles);

        assertEquals("[]", CurrentAuthContext.getResourceAccess());
    }

    @Test
    void testGetRolesWhenAuthoritiesIsNull() {
        when(securityContext.getAuthentication()).thenReturn(authentication);
        when(authentication.getAuthorities()).thenReturn(null);

        assertEquals("[]", CurrentAuthContext.getRoles());
    }

    @Test
    void testGetHeadersWhenHeadersIsNull() {
        when(securityContext.getAuthentication()).thenReturn(authentication);

        Jwt jwtNoHeaders = mock(Jwt.class);
        when(jwtNoHeaders.getHeaders()).thenReturn(null);
        when(authentication.getPrincipal()).thenReturn(jwtNoHeaders);

        assertEquals("{}", CurrentAuthContext.getHeaders());
    }
}
