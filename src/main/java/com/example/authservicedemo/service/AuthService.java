package com.example.authservicedemo.service;

import com.example.authservicedemo.dto.*;
import com.example.authservicedemo.entity.*;
import com.example.authservicedemo.repository.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.security.auth.RefreshFailedException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HexFormat;
import java.util.UUID;

@Service
public class AuthService {
    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    @Value("${application.jwt.refresh-token-expiration}")
    private long refreshTokenExpiration;

    public AuthService(UserRepository userRepository,
                       RefreshTokenRepository refreshTokenRepository,
                       PasswordEncoder passwordEncoder,
                       JwtService jwtService) {
        this.userRepository = userRepository;
        this.refreshTokenRepository = refreshTokenRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
    }

    @Transactional
    public AuthResponse register(RegisterRequest req) {
        if(userRepository.existsByUsername(req.username())) {
            throw new RuntimeException("Username has been exist !");
        }
        if(userRepository.existsByEmail(req.email())) {
            throw new RuntimeException("Email has been used !");
        }
        User user = User.builder()
                .username(req.username())
                .email(req.email())
                .passwordHash(passwordEncoder.encode(req.password()))
                .departmentId(req.departmentId())
                .role(UserRole.valueOf(req.role().toUpperCase()))
                .build();

        userRepository.save(user);
        return generateTokensAndSave(user);
    }

    @Transactional
    public AuthResponse login(LoginRequest req) {
        User user = userRepository.findByUsername(req.username())
                .orElseThrow(() -> new RuntimeException("Wrong Username or Password !"));

        if(!passwordEncoder.matches(req.password(), user.getPasswordHash())) {
            throw new RuntimeException("Wrong Username or Password !");
        }

        return generateTokensAndSave(user);
    }

    @Transactional
    public AuthResponse refreshToken(RefreshTokenRequest req) {
        String tokenHash = hashSha256(req.refreshToken());

        RefreshToken oldToken = refreshTokenRepository.findByTokenHash(tokenHash)
                .orElseThrow(() -> new RuntimeException("Refresh token is not invalid !"));

        if(oldToken.isRevoked() || oldToken.getReplacedBy() != null) {
            User user = userRepository.findById(oldToken.getUserId()).orElseThrow();
            user.setTokenVersion(user.getTokenVersion() + 1);
            userRepository.save(user);
            throw new RuntimeException("Security warning: this token has been used. Revoked all login session !");
        }

        if(oldToken.isExpired()) {
            throw new RuntimeException("Refresh token is due, please login again !");
        }

        User user = userRepository.findById(oldToken.getUserId())
                .orElseThrow(() -> new RuntimeException("User does not exist !"));

        String newAccessToken = jwtService.generateAccessToken(user);
        String newRawRefreshToken = UUID.randomUUID().toString();
        String newRefreshTokenHash = hashSha256(newRawRefreshToken);

        RefreshToken newToken = RefreshToken.builder()
                .userId(user.getId())
                .tokenHash(newRefreshTokenHash)
                .expiresAt(Instant.now().plusMillis(refreshTokenExpiration))
                .build();
        refreshTokenRepository.save(newToken);

        oldToken.setRevokedAt(Instant.now());
        oldToken.setReplacedBy(newToken.getId());
        refreshTokenRepository.save(oldToken);

        return AuthResponse.of(newAccessToken, newRawRefreshToken);
    }

    private AuthResponse generateTokensAndSave(User user) {
        String accessToken = jwtService.generateAccessToken(user);
        String rawRefreshToken = UUID.randomUUID().toString();
        RefreshToken refreshToken = RefreshToken.builder()
                .userId(user.getId())
                .tokenHash(hashSha256(rawRefreshToken))
                .expiresAt(Instant.now().plusMillis(refreshTokenExpiration))
                .build();
        refreshTokenRepository.save(refreshToken);
        return AuthResponse.of(accessToken, rawRefreshToken);
    }

    private String hashSha256(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] encodedhash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(encodedhash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Error encrypt algorithm", e);
        }
    }
}
