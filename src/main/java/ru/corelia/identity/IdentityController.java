package ru.corelia.identity;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import ru.corelia.http.ApiRequest;

import tools.jackson.databind.JsonNode;

/** Внутренний API сессии, доступный только доверенному gateway. */
@RestController
@RequestMapping("/internal/v1/auth")
public class IdentityController {
    private final IdentityProvider provider;
    private final ApiRequest requests;

    public IdentityController(IdentityProvider provider, ApiRequest requests) {
        this.provider = provider;
        this.requests = requests;
    }

    @PostMapping("/login")
    public JsonNode login(HttpServletRequest request) {
        return provider.login(requests.body(request));
    }

    @PostMapping("/refresh")
    public JsonNode refresh(HttpServletRequest request) {
        return provider.refresh(requests.body(request));
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(HttpServletRequest request) {
        provider.logout(requests.body(request));
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/me")
    public JsonNode user(HttpServletRequest request) {
        return requests.auth(request).user();
    }
}
