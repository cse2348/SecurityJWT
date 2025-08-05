package jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

// 매 요청(Request)마다 JWT 토큰을 검사하고, 인증 정보를 SecurityContextHolder에 저장하는 파일
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;  // 토큰을 생성, 검증, 파싱하는 유틸 클래스
    private final UserDetailsService userDetailsService;  // 유저 정보를 DB에서 가져오는 서비스

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        // 요청 헤더에서 Authorization 정보를 가져오기
        String header = request.getHeader("Authorization");

        // Authorization 헤더가 존재하고, Bearer로 시작하는지 체크
        if (header != null && header.startsWith("Bearer ")) {
            // Bearer 다음 부분이 토큰 문자열
            String token = header.substring(7);

            // 토큰 유효성 검사 (서명 검증, 만료시간 확인 등)
            if (jwtUtil.validateToken(token)) {
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

        // 다음 필터로 요청 넘기기
        filterChain.doFilter(request, response);
    }
}
