package com.example.securityjwt.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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

    private static final Logger log = LoggerFactory.getLogger(JwtAuthenticationFilter.class);
    private final JwtUtil jwtUtil;

    // 요청이 들어올 때마다 한 번만 실행되는 필터 -> JWT 토큰 검증 후 SecurityContext에 인증 정보 저장
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String path = request.getRequestURI();

        // OAuth2 콜백 경로는 JWT 검증 없이 통과
        if (path != null && path.startsWith("/oauth2/callback/")) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = null;
        try {
            // Access Token 추출 (쿠키 → 헤더 순서)
            token = resolveAccessToken(request);

            // 토큰 존재 + 유효성 검증 + AccessToken 타입 확인
            if (token != null && jwtUtil.validateToken(token) && jwtUtil.isAccessToken(token)) {
                Long userId = jwtUtil.getUserIdFromToken(token);
                String role = jwtUtil.getUserRoleFromToken(token);

                if (userId != null) {
                    // 인증 주체(Principal) 생성
                    JwtPrincipal principal = new JwtPrincipal(userId);

                    // 권한 목록 생성
                    List<GrantedAuthority> authorities = (role != null && !role.isBlank())
                            ? List.of(new SimpleGrantedAuthority(role))
                            : Collections.emptyList();

                    // Spring Security 인증 객체 생성 후 저장
                    var authentication = new UsernamePasswordAuthenticationToken(principal, null, authorities);
                    SecurityContextHolder.getContext().setAuthentication(authentication);

                    log.info("SecurityContext에 인증 정보 저장 완료 - userId: {}", userId);
                }
            }
        } catch (Exception e) {
            // 토큰이 없거나 검증 실패 시 예외 처리
            log.error("JWT 인증 필터 처리 중 에러 발생 - 토큰: {}", token, e);
        }

        // 다음 필터로 요청 전달
        filterChain.doFilter(request, response);
    }

    // Access Token 추출 1. 쿠키(ACCESS_TOKEN) → 2. Authorization 헤더 순서
    private String resolveAccessToken(HttpServletRequest request) {
        // 쿠키에서 검색
        if (request.getCookies() != null) {
            for (Cookie c : request.getCookies()) {
                if ("ACCESS_TOKEN".equals(c.getName())) {
                    String v = c.getValue();
                    if (v != null && !v.isBlank()) return v.trim();
                }
            }
        }
        // 헤더에서 검색
        String header = request.getHeader("Authorization");
        if (header != null && header.startsWith("Bearer ")) {
            return header.substring(7).trim();
        }
        return null;
    }

    // SecurityContext에 저장할 사용자 식별 정보
    public record JwtPrincipal(Long userId) {}
}
