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

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String path = request.getRequestURI();

        if (path != null && path.startsWith("/oauth2/callback/")) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = null;
        try {
            // 헤더 또는 쿠키에서 Access Token 추출
            token = resolveAccessToken(request);

            // 토큰이 존재하고, 유효하며, Access Token 타입일 경우에만 인증 처리
            if (token != null && jwtUtil.validateToken(token) && jwtUtil.isAccessToken(token)) {
                Long userId = jwtUtil.getUserIdFromToken(token);
                String role = jwtUtil.getUserRoleFromToken(token);

                if (userId != null) {
                    // Spring Security가 이해할 수 있는 Authentication 객체 생성
                    JwtPrincipal principal = new JwtPrincipal(userId);
                    List<GrantedAuthority> authorities = (role != null && !role.isBlank())
                            ? List.of(new SimpleGrantedAuthority(role))
                            : Collections.emptyList();

                    var authentication = new UsernamePasswordAuthenticationToken(principal, null, authorities);
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                    log.info(">>>> SecurityContext에 인증 정보 저장 완료! userId: {}", userId);
                }
            }
        } catch (Exception e) {
            // 토큰이 없거나 유효하지 않은 경우, 예외 발생
            log.error("!!!!!!!! JWT 인증 필터에서 에러 발생! 토큰: {} !!!!!!!!", token, e);
        }

        filterChain.doFilter(request, response);
    }

    private String resolveAccessToken(HttpServletRequest request) {
        // 쿠키에서 먼저 찾아봄
        if (request.getCookies() != null) {
            for (Cookie c : request.getCookies()) {
                if ("ACCESS_TOKEN".equals(c.getName())) {
                    String v = c.getValue();
                    if (v != null && !v.isBlank()) return v.trim();
                }
            }
        }
        // 쿠키에 없으면 헤더에서 찾아봄
        String header = request.getHeader("Authorization");
        if (header != null && header.startsWith("Bearer ")) {
            return header.substring(7).trim();
        }
        return null;
    }

    // SecurityContext에 저장될 Principal 객체
    public record JwtPrincipal(Long userId) {}
}
