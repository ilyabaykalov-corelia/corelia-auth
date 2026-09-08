package ru.corelia.identity;

import static ru.corelia.support.Json.*;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;

import ru.corelia.auth.JwtVerifier;
import ru.corelia.config.CoreliaConfig;
import ru.corelia.http.ApiException;
import ru.corelia.integration.PlatformHttp;
import ru.corelia.support.LogJson;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.ObjectNode;

import java.util.*;

/** Адаптер текущего Keycloak Direct Access Grants. Пароли и токены постоянно не сохраняются. */
@Service
@ConditionalOnProperty(
        name = "CORELIA_AUTH_PROVIDER",
        havingValue = "keycloak",
        matchIfMissing = true)
public class KeycloakIdentityProvider implements IdentityProvider {
    private final CoreliaConfig config;
    private final PlatformHttp http;
    private final JwtVerifier verifier;

    public KeycloakIdentityProvider(CoreliaConfig config, PlatformHttp http, JwtVerifier verifier) {
        this.config = config;
        this.http = http;
        this.verifier = verifier;
    }

    public ObjectNode login(JsonNode body) {
        String username = text(body, "username"), password = text(body, "password");
        if (username.isEmpty() || password.isEmpty())
            throw new ApiException(400, "Введите логин и пароль");
        return session(
                form(
                        "TOKEN",
                        Map.of(
                                "grant_type",
                                "password",
                                "username",
                                username,
                                "password",
                                password,
                                "scope",
                                config.value(
                                        "PLATFORM_V_KEYCLOAK_SCOPE",
                                        "openid profile email roles"))),
                "Keycloak direct access token context");
    }

    public ObjectNode refresh(JsonNode body) {
        String token = text(body, "refreshToken");
        if (token.isEmpty()) throw new ApiException(400, "Не передан refresh token");
        return session(
                form(
                        "TOKEN",
                        Map.of(
                                "grant_type",
                                "refresh_token",
                                "refresh_token",
                                token,
                                "scope",
                                config.value(
                                        "PLATFORM_V_KEYCLOAK_SCOPE",
                                        "openid profile email roles"))),
                "Keycloak refreshed access token context");
    }

    public void logout(JsonNode body) {
        String token = text(body, "refreshToken");
        if (!token.isEmpty() && !config.keycloak("LOGOUT").isEmpty()) {
            // Как в исходном API: локальный выход завершается даже при недоступном Keycloak.
            try {
                form("LOGOUT", Map.of("refresh_token", token));
            } catch (ApiException ignored) {
            }
        }
    }

    private JsonNode form(String endpoint, Map<String, String> params) {
        Map<String, String> fields = new LinkedHashMap<>();
        fields.put("client_id", config.clientId());
        String secret = config.value("PLATFORM_V_KEYCLOAK_CLIENT_SECRET");
        if (!secret.isEmpty()) fields.put("client_secret", secret);
        fields.putAll(params);
        String body =
                String.join(
                        "&",
                        fields.entrySet().stream()
                                .filter(entry -> !entry.getValue().isEmpty())
                                .map(
                                        entry ->
                                                encode(entry.getKey())
                                                        + "="
                                                        + encode(entry.getValue()))
                                .toList());
        return http.json(
                config.required(
                        "PLATFORM_V_KEYCLOAK_" + endpoint + "_URL", config.keycloak(endpoint)),
                "POST",
                body,
                Map.of(
                        "Accept",
                        "application/json",
                        "Content-Type",
                        "application/x-www-form-urlencoded"));
    }

    private ObjectNode session(JsonNode tokens, String logMessage) {
        String token = text(tokens, "access_token");
        if (token.isEmpty()) throw new ApiException(502, "Keycloak не вернул access_token");
        long now = System.currentTimeMillis(), expires = number(tokens, "expires_in", 0);
        var auth = verifier.authenticate("Bearer " + token);
        ObjectNode result =
                object(
                        "accessToken",
                        token,
                        "tokenType",
                        fallback(text(tokens, "token_type"), "Bearer"),
                        "expiresIn",
                        expires,
                        "expiresAt",
                        now + Math.max(0, expires) * 1000,
                        "user",
                        auth.user());
        LogJson.info(
                logMessage,
                object(
                        "username", auth.login(),
                        "userId", auth.id(),
                        "roleCount", auth.roles().size(),
                        "expiresIn", expires,
                        "hasRefreshToken", tokens.has("refresh_token")));
        Map.of(
                        "refresh_token",
                        "refreshToken",
                        "id_token",
                        "idToken",
                        "scope",
                        "scope",
                        "refresh_expires_in",
                        "refreshExpiresIn")
                .forEach(
                        (source, target) -> {
                            if (tokens.has(source)) result.set(target, tokens.path(source));
                        });
        long refresh = number(tokens, "refresh_expires_in", 0);
        if (refresh > 0) result.put("refreshExpiresAt", now + refresh * 1000);
        return result;
    }
}
