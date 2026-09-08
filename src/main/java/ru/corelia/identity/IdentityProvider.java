package ru.corelia.identity;

import tools.jackson.databind.JsonNode;

/** Контракт провайдера входа. Изменение провайдера не меняет клиентский API Corelia. */
public interface IdentityProvider {
    JsonNode login(JsonNode payload);

    JsonNode refresh(JsonNode payload);

    void logout(JsonNode payload);
}
