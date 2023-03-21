package net.uglevodov.api.security;

import net.uglevodov.api.config.JwtConfig;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;

public class JwtAuthenticationWebFilter extends AuthenticationWebFilter {

    public JwtAuthenticationWebFilter(JwtConfig jwtConfig) {
        super(reactiveAuthenticationManager(jwtConfig));

        setRequiresAuthenticationMatcher(jwtServerWebExchangeMatcher());
        setServerAuthenticationConverter(jwtServerAuthenticationConverter(jwtConfig));
    }

    private static ReactiveAuthenticationManager reactiveAuthenticationManager(JwtConfig jwtConfig) {
        return new JwtReactiveAuthenticationManager(jwtConfig);
    }

    private static ServerWebExchangeMatcher jwtServerWebExchangeMatcher() {
        return new JwtServerWebExchangeMatcher();
    }

    private static ServerAuthenticationConverter jwtServerAuthenticationConverter(JwtConfig jwtConfig) {
        return new JwtServerAuthenticationConverter();
    }
}
