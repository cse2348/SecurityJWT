package com.example.securityjwt.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

// 매 요청(Request)마다 JWT 토큰을 검사하고, 인증 정보를 SecurityContextHolder에 저장시킴
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;  // 토큰을 생성, 검증, 파싱하는 유틸 클래스
    private final UserDetailsService userDetailsService;  // 유저 정보를 DB에서 가져오는 서비스

    // /auth/** 경로(로그인/회원가입/리프레시)는 필터 패스 (리프레시 로직 방해 금지)
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        String uri = request.getRequestURI();
        return uri.startsWith("/auth/");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        try {
            // 이미 인증되어 있으면 스킵
            if (SecurityContextHolder.getContext().getAuthentication() == null) {

                // 요청 헤더에서 Authorization 정보를 가져오기
                String header = request.getHeader("Authorization");

                // Authorization 헤더가 존재하고, Bearer로 시작하는지 체크
                if (header != null && header.startsWith("Bearer ")) {
                    // Bearer 다음 부분이 토큰 문자열
                    String token = header.substring(7).trim();

                    // 토큰 유효성 검사 (서명 검증, 만료시간 확인 등)
                    if (jwtUtil.validateToken(token)) {

                        // (권장) access 토큰만 인증 처리 — refresh 토큰이면 통과만
                        boolean isAccess = true;
                        try {
                            // JwtUtil에 tokenType 클레임을 넣었다면 활성화
                            isAccess = jwtUtil.isAccessToken(token);
                        } catch (Throwable ignore) {
                            // 구버전 JwtUtil(클레임 미구현) 호환: isAccess 체크 실패 시 그냥 진행
                        }

                        if (isAccess) {
                            // 토큰에서 username (혹은 userId)를 파싱
                            String username = jwtUtil.getUsernameFromToken(token);

                            // username으로 DB에서 사용자 정보를 조회
                            UserDetails userDetails = userDetailsService.loadUserByUsername(username);

                            // 인증 객체 생성(비밀번호는 null, 권한 정보 포함)
                            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                                    userDetails, null, userDetails.getAuthorities());

                            // SecurityContextHolder에 인증 객체 저장 → 로그인한 상태로 인식
                            SecurityContextHolder.getContext().setAuthentication(authentication);
                        }
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
}
