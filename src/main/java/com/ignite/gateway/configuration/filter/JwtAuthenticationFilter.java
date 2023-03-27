package com.ignite.gateway.configuration.filter;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Mono;

import java.util.Objects;

/**
 * Jwt authentication filter
 */
@Component
@Slf4j
public class JwtAuthenticationFilter extends AbstractGatewayFilterFactory<JwtAuthenticationFilter.Config> {

    private static final String AUTH_URL = "http://localhost:8081/hill-top-user/api/v1/user/validate-token?token=";
    @Autowired
    private RouteValidator routeValidator;
    @Autowired
    private RestTemplate restTemplate;

    public JwtAuthenticationFilter() {
        super(Config.class);
    }

    /**
     * This method is used to validate api tokens by calling user service.
     *
     * @param config config
     * @return success/ error message.
     */
    @Override
    public GatewayFilter apply(Config config) {
        return ((exchange, chain) -> {
            if (routeValidator.isSecured.test(exchange.getRequest())) {
                if (!exchange.getRequest().getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                    return Mono.error(new ResponseStatusException(HttpStatus.UNAUTHORIZED,
                            "Authorization token header missing"));
                }
                String authHeader = Objects.requireNonNull(exchange.getRequest().getHeaders()
                        .get(HttpHeaders.AUTHORIZATION)).get(0);
                if (authHeader != null && authHeader.startsWith("Bearer ")) {
                    authHeader = authHeader.substring(7);
                }
                try {
                    restTemplate.getForObject(AUTH_URL + authHeader, String.class);
                } catch (HttpClientErrorException e) {
                    log.error("Token validation failed from user service. Error message: {}", e.getMessage());
                    if (e.getStatusCode().equals(HttpStatus.UNAUTHORIZED))
                        return Mono.error(new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid token", e));
                    return Mono.error(
                            new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "An error occurred", e));
                }
            }
            return chain.filter(exchange);
        });
    }

    public static class Config {
    }
}
