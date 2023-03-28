package com.ignite.gateway.configuration.filter;

import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.function.Predicate;

/**
 * Route validator
 */
@Component
public class RouteValidator {

    private static final List<String> openApiEndpoints = List.of(
            "/api/v1/user",
            "/api/v1/user/login",
            "/api/v1/user/validate-token",
            "/eureka",
            "/swagger-ui/",
            "/swagger-ui.html",
            "/swagger-resources",
            "/v3/api-docs",
            "/v2/api-docs"
    );

    public static final Predicate<ServerHttpRequest> isSecured =
            request -> openApiEndpoints
                    .stream()
                    .noneMatch(uri -> request.getURI().getPath().contains(uri));

    private RouteValidator() {
    }
}
