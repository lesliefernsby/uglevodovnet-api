package net.uglevodov.api.config;


import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix = "spring.security.jwt")

public class JwtConfig {

    @Getter @Setter
    private String secret;
    @Getter @Setter
    private int accessTokenExpiration;
    @Getter @Setter
    private int refreshTokenExpiration;
}
