package net.uglevodov.api.security;
import net.uglevodov.api.config.JwtConfig;
import net.uglevodov.api.model.User;
import net.uglevodov.api.repository.UserRepository;
import net.uglevodov.api.util.JwtUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import reactor.core.publisher.Mono;

import java.util.Collections;

public class JwtReactiveAuthenticationManager implements ReactiveAuthenticationManager {

    @Autowired
    UserRepository userRepository;
    private final JwtUtils jwtUtils;

    public JwtReactiveAuthenticationManager(JwtConfig jwtConfig) {
        this.jwtUtils = new JwtUtils(jwtConfig);
    }

    @Override
    public Mono<Authentication> authenticate(Authentication authentication) {
        String token = (String) authentication.getCredentials();
        String username = jwtUtils.getUsernameFromToken(token);

        return userRepository.findByUsername(username)
                .switchIfEmpty(Mono.<User>error(new UsernameNotFoundException("User not found")))
                .filter(user -> jwtUtils.validateToken(token))
                .map(user -> new UsernamePasswordAuthenticationToken(
                        createUserDetails(user),
                        null,
                        Collections.singletonList(new SimpleGrantedAuthority(user.getRole().toString()))
                ));
    }

    private UserDetails createUserDetails(User user) {
        return org.springframework.security.core.userdetails.User.builder()
                .username(user.getUsername())
                .password(user.getPassword())
                .authorities((GrantedAuthority) Collections.singleton(user.getRole().toString()))
                .build();
    }
}

