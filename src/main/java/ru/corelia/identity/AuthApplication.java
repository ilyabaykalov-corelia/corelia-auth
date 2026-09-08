package ru.corelia.identity;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import ru.corelia.config.LocalEnvironment;

/** Запускает приложение corelia-auth. */
@SpringBootApplication(
        scanBasePackages = {
            "ru.corelia.config",
            "ru.corelia.profile",
            "ru.corelia.support",
            "ru.corelia.auth",
            "ru.corelia.http",
            "ru.corelia.cache",
            "ru.corelia.integration",
            "ru.corelia.transport",
            "ru.corelia.identity"
        })
public class AuthApplication {
    public static void main(String[] args) {
        var app = new SpringApplication(AuthApplication.class);
        app.setDefaultProperties(LocalEnvironment.load());
        app.run(args);
    }
}
