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

// 매 요청마다 JWT 토큰을 검사해 인증 정보를 SecurityContextHolder에 저장 -> JwtUtil로 토큰 검증/파싱
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil; // 토큰 생성/검증/파싱 유틸

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        String uri = request.getRequestURI();
        if ("OPTIONS".equalsIgnoreCase(request.getMethod())) return true;
        return uri.equals("/auth/login")
                || uri.equals("/auth/signup")
                || uri.equals("/auth/refresh")
                || uri.startsWith("/oauth2/")
                || uri.equals("/health")
                || uri.equals("/actuator/health");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        try {
            // 이미 인증되어 있으면 스킵
            if (SecurityContextHolder.getContext().getAuthentication() == null) {
                // 토큰 추출 (쿠키 우선 → Authorization 헤더)
                String token = resolveAccessToken(request);

                // 토큰이 없으면 그냥 다음 필터로 통과
                if (token == null || token.isBlank()) {
                    filterChain.doFilter(request, response);
                    return;
                }

                // 토큰 유효성 & 타입 검증
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

                        // 가벼운 Principal (DB 조회 없이)
                        JwtPrincipal principal = new JwtPrincipal(userId);

                        var authentication = new UsernamePasswordAuthenticationToken(principal, null, authorities);
                        SecurityContextHolder.getContext().setAuthentication(authentication);
                    }
                }
            }
        } catch (Exception ignored) {
            // 여기서 예외를 던지면 500 가능 → 로깅만 하고 진행
        }

        filterChain.doFilter(request, response);
    }

    // Access 토큰 추출
    private String resolveAccessToken(HttpServletRequest request) {
        // 쿠키
        if (request.getCookies() != null) {
            for (Cookie c : request.getCookies()) {
                if ("ACCESS_TOKEN".equals(c.getName())) {
                    String v = c.getValue();
                    if (v != null && !v.isBlank()) return v.trim();
                }
            }
        }
        // 헤더
        String header = request.getHeader("Authorization");
        if (header != null && header.startsWith("Bearer ")) {
            return header.substring(7).trim();
        }
        return null;
    }

    public record JwtPrincipal(Long userId) {}
}
