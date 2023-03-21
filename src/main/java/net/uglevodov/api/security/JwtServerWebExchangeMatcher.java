package net.uglevodov.api.security;
import org.springframework.http.HttpHeaders;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

public class JwtServerWebExchangeMatcher implements ServerWebExchangeMatcher {

    @Override
    public Mono<MatchResult> matches(ServerWebExchange exchange) {
        return Mono.just(exchange)
                .filter(e -> e.getRequest().getHeaders().containsKey(HttpHeaders.AUTHORIZATION))
                .flatMap(e -> MatchResult.match())
                .switchIfEmpty(MatchResult.notMatch());
    }
}
