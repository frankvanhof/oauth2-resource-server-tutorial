package com.example.oauth2resourceservertutorial.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.oauth2resourceservertutorial.utils.auth.CurrentAuthContext;

@RestController
public class MainController {

    @GetMapping("/public")
    public String homePage() {
        return "Hello from Spring boot app";
    }

    @GetMapping("/private")
    public String privateRoute() {
        return CurrentAuthContext.getClaims();
    }

    @GetMapping("/scope")
    public String scopeRoute() {
        return CurrentAuthContext.getScope();
    }

    @GetMapping("/email")
    public String emailRoute() {
        return CurrentAuthContext.getUserEmail();
    }

    @GetMapping("/roles")
    public String rolRoute() {
        return CurrentAuthContext.getRoles();
    }

    @GetMapping("/authentication")
    public String authenticationRoute() {
        return CurrentAuthContext.getAuthentication();
    }

    @GetMapping("/headers")
    public String headersRoute() {
        return CurrentAuthContext.getHeaders();
    }

    @GetMapping("/hasclaim")
    public String hasClaimRoute() {
        return CurrentAuthContext.hasClaim();
    }

    @GetMapping("/resourceaccess")
    public String resourceAccessRoute() {
        return CurrentAuthContext.getResourceAccess();
    }
}
