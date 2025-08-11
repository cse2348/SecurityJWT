package com.example.securityjwt.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

/**
 * 매 요청(Request)마다 JWT 토큰을 검사하고,
 * 인증 정보를 SecurityContextHolder에 저장시킴
 *
 * - 2주차 흐름 반영:
 *   1) 쿠키(ACCESS_TOKEN) 우선 → 없으면 Authorization: Bearer
 *   2) Access 토큰만 인증 처리(Refresh는 재발급 전용)
 *   3) DB 조회 없이 무상태 인증 (UserDetailsService 제거)
 *   4) /auth(login|signup|refresh), /oauth2/**, /health, /actuator/health, OPTIONS는 필터 패스
 */
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;  // 토큰을 생성, 검증, 파싱하는 유틸 클래스

    // 로그인/회원가입/리프레시 + OAuth2 콜백/시작 + 헬스체크 + OPTIONS는 필터 패스
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        String uri = request.getRequestURI();
        if ("OPTIONS".equalsIgnoreCase(request.getMethod())) return true;

        return uri.equals("/auth/login")
                || uri.equals("/auth/signup")
                || uri.equals("/auth/refresh")
                || uri.startsWith("/oauth2/")          // 소셜 로그인 시작/콜백
                || uri.equals("/health")
                || uri.equals("/actuator/health");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        try {
            // 이미 인증되어 있으면 스킵
            if (SecurityContextHolder.getContext().getAuthentication() == null) {
                // 1) 토큰 추출 (쿠키 → 헤더 순)
                String token = resolveAccessToken(request);

                // 2) 토큰 유효성 검사
                if (token != null && jwtUtil.validateToken(token) && jwtUtil.isAccessToken(token)) {
                    // 3) 토큰에서 userId/role 추출
                    Long userId = jwtUtil.getUserIdFromToken(token);
                    String role = jwtUtil.getUserRoleFromToken(token);
                    if (userId != null) {
                        // 4) DB 조회 없이 가벼운 Principal 구성 → 무상태 인증
                        JwtPrincipal principal = new JwtPrincipal(userId);
                        var authorities = (role != null)
                                ? List.of(new SimpleGrantedAuthority(role))
                                : List.of();

                        // 비밀번호는 null, 권한 정보 포함
                        var authentication = new UsernamePasswordAuthenticationToken(principal, null, authorities);

                        // SecurityContextHolder에 인증 객체 저장 → 로그인한 상태로 인식
                        SecurityContextHolder.getContext().setAuthentication(authentication);
                    }
                }
            }
        } catch (Exception e) {
            // 여기서 예외를 던지면 500이 날 수 있으니 로깅만 하고 필터 체인은 계속 진행
            // log.warn("[JWT] authentication filter error: {}", e.getMessage());
        }

        // 다음 필터로 요청 넘기기
        filterChain.doFilter(request, response);
    }

    /**
     * Access 토큰을 요청에서 추출
     * - 1순위: HttpOnly 쿠키 ACCESS_TOKEN (OAuth2 성공 핸들러가 심어줌)
     * - 2순위: Authorization: Bearer {token}
     */
    private String resolveAccessToken(HttpServletRequest request) {
        // 쿠키 우선
        if (request.getCookies() != null) {
            for (Cookie c : request.getCookies()) {
                if ("ACCESS_TOKEN".equals(c.getName())) {
                    String v = c.getValue();
                    if (v != null && !v.isBlank()) return v.trim();
                }
            }
        }
        // 헤더(모바일/테스트 클라이언트 등)
        String header = request.getHeader("Authorization");
        if (header != null && header.startsWith("Bearer ")) {
            return header.substring(7).trim();
        }
        return null;
    }

    /**
     * SecurityContext에 저장될 가벼운 Principal
     * - 굳이 UserDetails/엔티티를 넣지 않고 userId만 보관
     * - 컨트롤러에서 필요하면 Authentication.getPrincipal() 캐스팅해서 id 사용
     */
    public record JwtPrincipal(Long userId) {}
}
