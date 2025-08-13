package com.example.securityjwt.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;
import java.util.List;

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String uri = request.getRequestURI();
        return uri.startsWith("/oauth2/") ||
                uri.equals("/auth/login") ||
                uri.equals("/auth/signup") ||
                uri.equals("/auth/refresh") ||
                uri.equals("/health") ||
                uri.equals("/actuator/health") ||
                "OPTIONS".equalsIgnoreCase(request.getMethod());
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        try {
            if (SecurityContextHolder.getContext().getAuthentication() == null) {
                String token = resolveAccessToken(request);
                if (token == null || token.isBlank()) {
                    filterChain.doFilter(request, response);
                    return;
                }
                if (jwtUtil.validateToken(token) && jwtUtil.isAccessToken(token)) {
                    Long userId = jwtUtil.getUserIdFromToken(token);
                    String role = jwtUtil.getUserRoleFromToken(token);
                    if (userId != null) {
                        String normalizedRole = (role != null && !role.isBlank())
                                ? (role.startsWith("ROLE_") ? role : "ROLE_" + role)
                                : null;
                        List<GrantedAuthority> authorities =
                                (normalizedRole != null)
                                        ? List.of(new SimpleGrantedAuthority(normalizedRole))
                                        : Collections.emptyList();
                        JwtPrincipal principal = new JwtPrincipal(userId);
                        var authentication = new UsernamePasswordAuthenticationToken(principal, null, authorities);
                        SecurityContextHolder.getContext().setAuthentication(authentication);
                    }
                }
            }
        } catch (Exception ignored) {}

        filterChain.doFilter(request, response);
    }

    private String resolveAccessToken(HttpServletRequest request) {
        if (request.getCookies() != null) {
            for (Cookie c : request.getCookies()) {
                if ("ACCESS_TOKEN".equals(c.getName())) {
                    String v = c.getValue();
                    if (v != null && !v.isBlank()) return v.trim();
                }
            }
        }
        String header = request.getHeader("Authorization");
        if (header != null && header.startsWith("Bearer ")) {
            return header.substring(7).trim();
        }
        return null;
    }

    public record JwtPrincipal(Long userId) {}
}
