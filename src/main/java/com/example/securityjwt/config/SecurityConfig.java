package com.example.securityjwt.config;

import com.example.securityjwt.jwt.JwtAuthenticationFilter;
import com.example.securityjwt.jwt.JwtUtil;
import com.example.securityjwt.oauth.CustomOAuth2UserService;
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

//  Spring Security 전역 보안 설정 -> 세션 미사용(STATELESS) + JWT 필터 + OAuth2 로그인(success handler로 JWT 발급)
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtUtil jwtUtil;

    // OAuth2 로그인에 필요한 컴포넌트들 주입
    private final CustomOAuth2UserService customOAuth2UserService;
    private final OAuth2SuccessHandler oAuth2SuccessHandler;

    // JwtAuthenticationFilter에는 @Component 달지 말고, 여기 @Bean만 사용 (체인에 한 번만 등록)
    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter() {
        // 매 요청에서 쿠키/헤더의 ACCESS_TOKEN만 검증하면 되므로 JwtUtil만 주입
        return new JwtAuthenticationFilter(jwtUtil);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        // 로컬 회원가입/로그인 비밀번호 암호화를 위해 필요(BCrypt)
        return new BCryptPasswordEncoder();
    }

    //CORS 설정 -> 프론트 도메인에서 브라우저로 쿠키를 사용하려면: allowCredentials=true, 도메인 명시, HTTPS 권장
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        // 배포/테스트 도메인 허용
        config.setAllowedOriginPatterns(List.of(
                "https://winnerteam.store"
        ));
        config.setAllowedMethods(List.of("GET","POST","PUT","DELETE","OPTIONS"));
        config.setAllowedHeaders(List.of("Authorization","Content-Type","Accept","Origin","X-Requested-With","Cache-Control"));
        config.setAllowCredentials(true); // 쿠키 전송 허용 (SameSite=None;Secure 쿠키와 함께 HTTPS 권장)

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }

// /auth/**, /oauth2/**, /health 등은 공개, 그 외는 인증 필요
// OAuth2 로그인 흐름 + 성공 시 JWT 쿠키 발급
// UsernamePasswordAuthenticationFilter 앞에 JWT 필터 등록

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // 세션 미사용 + CSRF/Form/Basic 비활성화 (JWT 기반)
                .csrf(csrf -> csrf.disable())
                .httpBasic(hb -> hb.disable())
                .formLogin(fl -> fl.disable())
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                // URL 접근 제어
                .authorizeHttpRequests(auth -> auth
                        // Preflight는 항상 허용
                        .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                        // 헬스체크는 반드시 허용
                        .requestMatchers("/health", "/actuator/health").permitAll()
                        // 공개 인증 API
                        .requestMatchers("/auth/login", "/auth/signup", "/auth/refresh").permitAll()
                        // OAuth2 로그인 시작/콜백 경로 허용
                        .requestMatchers("/oauth2/**").permitAll()
                        // 나머지는 인증 필요
                        .anyRequest().authenticated()
                )

                // OAuth2 로그인 설정
                .oauth2Login(oauth -> oauth
                                // /oauth2/authorize/{provider} 로 시작 (구글/카카오/네이버 버튼이 이 경로로 이동)
                                .authorizationEndpoint(ae -> ae.baseUri("/oauth2/authorize"))
                                // 소셜 콘솔에 등록한 redirect-uri와 매칭 (예: /oauth2/callback/google)
                                .redirectionEndpoint(re -> re.baseUri("/oauth2/callback/*"))
                                // 사용자 정보 파서(자동 회원가입 포함)
                                .userInfoEndpoint(ue -> ue.userService(customOAuth2UserService))
                                // 성공 시: JWT 쿠키 발급 + 프론트 성공 URL로 리다이렉트
                                .successHandler(oAuth2SuccessHandler)
                        // .failureHandler(oAuth2FailureHandler) // 필요 시 주석 해제
                )

                // 401/403을 JSON으로 명확히 내려주기 (디버깅 편의)
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

                // JWT 필터: UsernamePasswordAuthenticationFilter 앞에 등록
                .addFilterBefore(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
