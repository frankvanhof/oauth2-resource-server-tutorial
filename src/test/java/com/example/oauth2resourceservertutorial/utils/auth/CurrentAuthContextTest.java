package com.example.oauth2resourceservertutorial.utils.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Collections;
import java.util.Map;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;

class CurrentAuthContextTest {

    @BeforeEach
    void setUp() {
        SecurityContextHolder.clearContext();
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void getAuthentication_ReturnsNull_WhenNoAuth() {
        assertNull(CurrentAuthContext.getAuthentication());
    }

    @Test
    void getAuthentication_ReturnsAuth_WhenAuthenticated() {
        Authentication auth = mock(Authentication.class);
        SecurityContext context = mock(SecurityContext.class);
        when(context.getAuthentication()).thenReturn(auth);
        SecurityContextHolder.setContext(context);

        assertEquals(auth, CurrentAuthContext.getAuthentication());
    }

    @Test
    void getPrincipalJwt_ReturnsNull_WhenPrincipalNotJwt() {
        Authentication auth = mock(Authentication.class);
        when(auth.getPrincipal()).thenReturn("not-a-jwt");
        SecurityContext context = mock(SecurityContext.class);
        when(context.getAuthentication()).thenReturn(auth);
        SecurityContextHolder.setContext(context);

        // This is a private method, so we test it via public methods that use it
        assertNull(CurrentAuthContext.getScope());
    }

    @Test
    void hasClaim_ReturnsFalse_WhenNoJwt() {
        assertFalse(CurrentAuthContext.hasClaim("any"));
    }

    @Test
    void hasClaim_ReturnsTrue_WhenClaimExists() {
        Jwt jwt = mock(Jwt.class);
        when(jwt.hasClaim("test")).thenReturn(true);
        setupAuthWithJwt(jwt);

        assertTrue(CurrentAuthContext.hasClaim("test"));
    }

    @Test
    void getScope_ReturnsNull_WhenNoJwt() {
        assertNull(CurrentAuthContext.getScope());
    }

    @Test
    void getScope_ReturnsNull_WhenClaimMissing() {
        Jwt jwt = mock(Jwt.class);
        when(jwt.getClaims()).thenReturn(Collections.emptyMap());
        setupAuthWithJwt(jwt);

        assertNull(CurrentAuthContext.getScope());
    }

    @Test
    void getScope_ReturnsNull_WhenClaimsNull() {
        Jwt jwt = mock(Jwt.class);
        when(jwt.getClaims()).thenReturn(null);
        setupAuthWithJwt(jwt);

        assertNull(CurrentAuthContext.getScope());
    }

    @Test
    void getScope_ReturnsValue_WhenPresent() {
        Jwt jwt = mock(Jwt.class);
        when(jwt.getClaims()).thenReturn(Map.of("scope", "read write"));
        setupAuthWithJwt(jwt);

        assertEquals("read write", CurrentAuthContext.getScope());
    }

    @Test
    void getUserName_ReturnsNull_WhenNoJwt() {
        assertNull(CurrentAuthContext.getUserName());
    }

    @Test
    void getUserName_ReturnsNull_WhenClaimMissing() {
        Jwt jwt = mock(Jwt.class);
        when(jwt.getClaims()).thenReturn(Collections.emptyMap());
        setupAuthWithJwt(jwt);

        assertNull(CurrentAuthContext.getUserName());
    }

    @Test
    void getUserName_ReturnsValue_WhenPresent() {
        Jwt jwt = mock(Jwt.class);
        when(jwt.getClaims()).thenReturn(Map.of("preferred_username", "testuser"));
        setupAuthWithJwt(jwt);

        assertEquals("testuser", CurrentAuthContext.getUserName());
    }

    @Test
    void getClaims_ReturnsEmptyString_WhenNoJwt() {
        assertEquals("", CurrentAuthContext.getClaims());
    }

    @Test
    void getRoles_ReturnsEmptyArray_WhenNoAuth() {
        assertEquals("[]", CurrentAuthContext.getRoles());
    }

    @Test
    void getRoles_ReturnsEmptyArray_WhenAuthoritiesNull() {
        Authentication auth = mock(Authentication.class);
        when(auth.getAuthorities()).thenReturn(null);
        SecurityContext context = mock(SecurityContext.class);
        when(context.getAuthentication()).thenReturn(auth);
        SecurityContextHolder.setContext(context);

        assertEquals("[]", CurrentAuthContext.getRoles());
    }

    @Test
    void getTheAuthentication_ReturnsNA_WhenNoAuth() {
        assertEquals("N/A", CurrentAuthContext.getTheAuthentication());
    }

    @Test
    void getHeaders_ReturnsEmptyMap_WhenNoJwt() {
        assertEquals("{}", CurrentAuthContext.getHeaders());
    }

    @Test
    void getHeaders_ReturnsEmptyMap_WhenHeadersNull() {
        Jwt jwt = mock(Jwt.class);
        when(jwt.getHeaders()).thenReturn(null);
        setupAuthWithJwt(jwt);

        assertEquals("{}", CurrentAuthContext.getHeaders());
    }

    @Test
    void getResourceAccess_ReturnsEmptyArray_WhenNoJwt() {
        assertEquals("[]", CurrentAuthContext.getResourceAccess());
    }

    @Test
    void getResourceAccess_ReturnsValue_WhenPresent() {
        Jwt jwt = mock(Jwt.class);
        Map<String, Object> resourceAccess = Map.of("client", Map.of("roles", Collections.singletonList("user")));
        when(jwt.getClaim("resource_access")).thenReturn(resourceAccess);
        setupAuthWithJwt(jwt);

        assertEquals(resourceAccess.toString(), CurrentAuthContext.getResourceAccess());
    }

    private void setupAuthWithJwt(Jwt jwt) {
        Authentication auth = mock(Authentication.class);
        when(auth.getPrincipal()).thenReturn(jwt);
        SecurityContext context = mock(SecurityContext.class);
        when(context.getAuthentication()).thenReturn(auth);
        SecurityContextHolder.setContext(context);
    }
}
