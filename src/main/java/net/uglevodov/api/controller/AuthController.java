package net.uglevodov.api.controller;

import net.uglevodov.api.dto.LoginRequest;
import net.uglevodov.api.dto.RegisterRequest;
import net.uglevodov.api.model.User;
import net.uglevodov.api.model.UserRole;
import net.uglevodov.api.repository.UserRepository;
import net.uglevodov.api.util.JwtUtils;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import javax.validation.Valid;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final UserRepository userRepository;
    private final JwtUtils jwtUtils;
    private final PasswordEncoder passwordEncoder;

    public AuthController(UserRepository userRepository, JwtUtils jwtUtils, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.jwtUtils = jwtUtils;
        this.passwordEncoder = passwordEncoder;
    }

    @PostMapping("/login")
    public Mono<ResponseEntity<Map<String, String>>> login(@RequestBody LoginRequest loginRequest) {
        return userRepository.findByUsername(loginRequest.getUsername())
                .filter(u ->
                        passwordEncoder.matches(loginRequest.getPassword(), u.getPassword()))
                .map(u -> {
                    Map<String, String> tokens = new HashMap<>();
                    tokens.put("access_token", jwtUtils.generateAccessToken(u));
                    tokens.put("refresh_token", jwtUtils.generateRefreshToken(u));
                    return ResponseEntity.ok(tokens);
                })
                .defaultIfEmpty(ResponseEntity.status(HttpStatus.UNAUTHORIZED).build());
    }

    @PostMapping("/register")
    public Mono<ResponseEntity<String>> register(@Valid @RequestBody RegisterRequest registerRequest) {
        return userRepository.findByUsername(registerRequest.getUsername())
                .flatMap(u -> Mono.just(ResponseEntity.badRequest().body("Username already exists")))
                .switchIfEmpty(Mono.defer(() -> {
                    User user = new User();
                    user.setUsername(registerRequest.getUsername());
                    user.setPassword(passwordEncoder.encode(registerRequest.getPassword()));
                    user.setRole(UserRole.ROLE_USER);
                    return userRepository.save(user).map(savedUser -> {
                        String responseBody = "User " + savedUser.getUsername() + " created successfully";
                        return ResponseEntity.status(HttpStatus.CREATED).body(responseBody);
                    });
                }));
    }

}
