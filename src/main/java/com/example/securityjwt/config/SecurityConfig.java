package com.example.securityjwt.config;

import com.example.securityjwt.jwt.JwtAuthenticationFilter;
import com.example.securityjwt.jwt.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;

import jakarta.servlet.http.HttpServletResponse;
import java.util.List;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtUtil jwtUtil;  // JWT를 발급하고 검증하는 유틸 클래스
    private final UserDetailsService userDetailsService;  // 사용자 정보를 DB에서 가져오는 서비스

    // JwtAuthenticationFilter를 Bean으로 등록 ->직접 new를 통해 의존성(JwtUtil, UserDetailsService)을 주입해 반환
    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter() {
        return new JwtAuthenticationFilter(jwtUtil, userDetailsService);
    }

    // 비밀번호를 암호화할 때 사용할 PasswordEncoder를 Bean으로 등록 -> BCrypt 알고리즘을 사용하여 안전하게 비밀번호를 암호화/검증
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // CSRF(Cross-Site Request Forgery) 보안 비활성화 -> JWT를 사용하기 때문에 CSRF를 사용 X
                .csrf(csrf -> csrf.disable())
                // 기본 제공하는 HTTP Basic 인증 비활성화
                .httpBasic(httpBasic -> httpBasic.disable())
                // Form 기반 로그인 비활성화 (API 방식이므로 필요 없음)
                .formLogin(form -> form.disable())

                // CORS 설정 (Cross-Origin 요청 허용) -> 모든 Origin 허용 (배포 시에는 특정 도메인만 허용하는 것이 보안에 좋음)
                .cors(cors -> cors.configurationSource(request -> {
                    CorsConfiguration config = new CorsConfiguration();
                    config.setAllowedOriginPatterns(List.of("*"));  // 모든 도메인에서의 접근 허용
                    config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));  // 허용할 HTTP 메서드
                    config.setAllowedHeaders(List.of("*"));  // 모든 헤더 허용
                    config.setAllowCredentials(true);  // 쿠키 및 인증정보 허용 여부
                    return config;
                }))

                // 세션을 사용하지 않는 Stateless 방식으로 설정 - JWT를 사용하기 때문에 세션X
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                // URL별 접근 권한 설정
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()  // Preflight 요청 허용 (CORS Preflight)
                        .requestMatchers("/auth/**").permitAll()  // 로그인, 회원가입 API는 인증 없이 접근 가능
                        .anyRequest().authenticated()  // 나머지 모든 요청은 인증이 필요함
                )
                // 로그아웃 처리
                .logout(logout -> logout
                        .logoutSuccessHandler((request, response, authentication) -> {
                            response.setStatus(HttpServletResponse.SC_OK);  // 로그아웃 성공 시 200 OK 반환
                        })
                )
                // UsernamePasswordAuthenticationFilter 앞에 JWT 필터를 추가 -> 요청이 들어올 때마다 JWT 필터가 먼저 실행되어 토큰을 검증
                .addFilterBefore(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
        // SecurityFilterChain 빌드 후 반환
        return http.build();
    }
}
