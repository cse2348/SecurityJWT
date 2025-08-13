package com.example.securityjwt.config;

import com.example.securityjwt.jwt.JwtAuthenticationFilter;
import com.example.securityjwt.jwt.JwtUtil;
import com.example.securityjwt.oauth.CustomOAuth2UserService;
import com.example.securityjwt.oauth.OAuth2FailureHandler;
import com.example.securityjwt.oauth.OAuth2SuccessHandler;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    // JWT 유틸리티
    private final JwtUtil jwtUtil;

    // OAuth2 로그인 관련 서비스/핸들러
    private final CustomOAuth2UserService customOAuth2UserService;
    private final OAuth2SuccessHandler oAuth2SuccessHandler;
    private final OAuth2FailureHandler oAuth2FailureHandler;

    // JWT 인증 필터 (요청 시 토큰 검증)
    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter() {
        return new JwtAuthenticationFilter(jwtUtil);
    }

    // 비밀번호 암호화를 위한 BCrypt
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // CORS 설정 (프론트 도메인 허용)
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOriginPatterns(List.of("https://winnerteam.store"));
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        config.setAllowedHeaders(List.of("Authorization", "Content-Type", "Accept", "Origin", "X-Requested-With", "Cache-Control"));
        config.setAllowCredentials(true); // 쿠키 허용

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }

    // SecurityFilterChain 설정
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http
                // CSRF/폼로그인/HTTP Basic 인증 비활성화
                .csrf(csrf -> csrf.disable())
                .httpBasic(hb -> hb.disable())
                .formLogin(fl -> fl.disable())

                // CORS 적용
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))

                // OAuth 핸드셰이크 동안만 세션 허용 (authorization_request_not_found 방지)
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))

                // URL 접근 권한 설정
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll() // Preflight 허용
                        .requestMatchers("/health", "/actuator/health").permitAll() // 헬스 체크
                        .requestMatchers("/auth/login", "/auth/signup", "/auth/refresh").permitAll() // 공개 인증 API
                        // 요구사항: /oauth2/authorize/{provider} 시작/ /oauth2/callback/{provider} 콜백 허용
                        .requestMatchers("/oauth2/**").permitAll()
                        .anyRequest().authenticated() // 나머지는 인증 필요
                )

                // OAuth2 로그인 설정
                .oauth2Login(oauth -> oauth
                        // 요구사항: 로그인 시작 URL = /oauth2/authorize/{provider}
                        // (Spring 기본은 /oauth2/authorization/{provider} 이므로, 명시적으로 바꿔줌)
                        .authorizationEndpoint(ae -> ae.baseUri("/oauth2/authorize"))
                        // 콜백 URL = /oauth2/callback/{provider}
                        .redirectionEndpoint(re -> re.baseUri("/oauth2/callback/*"))
                        // 사용자 정보 처리
                        .userInfoEndpoint(ue -> ue.userService(customOAuth2UserService))
                        // 성공/실패 핸들러 (여기서 JWT 쿠키 발급/JSON 응답)
                        .successHandler(oAuth2SuccessHandler)
                        .failureHandler(oAuth2FailureHandler)
                )

                // 예외 처리 (401/403 JSON 응답)
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint((req, res, e) -> {
                            res.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                            res.setContentType("application/json;charset=UTF-8");
                            res.getWriter().write("{\"success\":false,\"message\":\"UNAUTHORIZED\",\"data\":null}");
                        })
                        .accessDeniedHandler((req, res, e) -> {
                            res.setStatus(HttpServletResponse.SC_FORBIDDEN);
                            res.setContentType("application/json;charset=UTF-8");
                            res.getWriter().write("{\"success\":false,\"message\":\"FORBIDDEN\",\"data\":null}");
                        })
                )

                // JWT 필터를 UsernamePasswordAuthenticationFilter 앞에 추가
                .addFilterBefore(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
