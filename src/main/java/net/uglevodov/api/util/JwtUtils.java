package net.uglevodov.api.util;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import net.uglevodov.api.config.JwtConfig;
import net.uglevodov.api.model.User;
import net.uglevodov.api.model.UserRole;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;


@Component
public class JwtUtils {

    private final JwtConfig jwtConfig;

    public JwtUtils(JwtConfig jwtConfig) {
        this.jwtConfig = jwtConfig;
    }

    public String generateAccessToken(User user) {
        return generateToken(user, jwtConfig.getAccessTokenExpiration());
    }

    public String generateRefreshToken(User user) {
        return generateToken(user, jwtConfig.getRefreshTokenExpiration());
    }

    private String generateToken(User user, int expirationInSeconds) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("role", user.getRole());

        String jwt = Jwts.builder()
                .setClaims(claims)
                .setSubject(user.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expirationInSeconds * 1000))
                .signWith(SignatureAlgorithm.HS256, jwtConfig.getSecret().getBytes(StandardCharsets.UTF_8))
                .compact();

        return Base64.getUrlEncoder().encodeToString(jwt.getBytes(StandardCharsets.UTF_8));
    }

    public String getUsernameFromToken(String token) {
        return getClaimsFromToken(token).getSubject();
    }

    public UserRole getRoleFromToken(String token) {
        Claims claims = getClaimsFromToken(token);
        return UserRole.valueOf((String) claims.get("role"));
    }

    public boolean validateToken(String token) {
        try {
            getClaimsFromToken(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private Claims getClaimsFromToken(String token) {
        String decodedJwt = new String(Base64.getUrlDecoder().decode(token), StandardCharsets.UTF_8);
        return Jwts.parser()
                .setSigningKey(jwtConfig.getSecret().getBytes(StandardCharsets.UTF_8))
                .parseClaimsJws(decodedJwt)
                .getBody();
    }
}
