package com.ignite.gateway.configuration.filter;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
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

    private static final String BEARER_PREFIX = "Bearer ";
    private static final String AUTHORIZATION_HEADER_MISSING = "Authorization token header missing";
    @Autowired
    private RestTemplate restTemplate;
    @Value("${userService.validateToken}")
    private String authUrl;

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
            if (RouteValidator.isSecured.test(exchange.getRequest())) {
                if (!exchange.getRequest().getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                    log.error(AUTHORIZATION_HEADER_MISSING);
                    return Mono.error(new ResponseStatusException(HttpStatus.UNAUTHORIZED, AUTHORIZATION_HEADER_MISSING));
                }
                String authHeader = Objects.requireNonNull(exchange.getRequest().getHeaders()
                        .get(HttpHeaders.AUTHORIZATION)).get(0);
                if (authHeader != null && authHeader.startsWith(BEARER_PREFIX)) {
                    authHeader = authHeader.substring(BEARER_PREFIX.length());
                }
                try {
                    restTemplate.getForObject(authUrl + authHeader, String.class);
                } catch (HttpClientErrorException e) {
                    log.error("Token validation failed from user service. Error message: {}", e.getMessage());
                    return sendUserServiceErrorResponse(e).then();
                }
            }
            return chain.filter(exchange);
        });
    }

    /**
     * This method is used to send error response according to user service error response.
     *
     * @param exception exception
     * @return response
     */
    private Mono<ResponseStatusException> sendUserServiceErrorResponse(HttpClientErrorException exception) {
        if (exception.getStatusCode().equals(HttpStatus.UNAUTHORIZED))
            return Mono.error(new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid token", exception));
        return Mono.error(
                new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "An error occurred", exception));
    }

    public static class Config {
    }
}
