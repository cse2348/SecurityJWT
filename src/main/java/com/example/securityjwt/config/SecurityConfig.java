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
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizationRequestRepository;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration @EnableWebSecurity @RequiredArgsConstructor
public class SecurityConfig {

    private final JwtUtil jwtUtil;
    private final CustomOAuth2UserService customOAuth2UserService;
    private final OAuth2SuccessHandler oAuth2SuccessHandler;
    private final OAuth2FailureHandler oAuth2FailureHandler;

    // OAuth 인가요청 저장소: 세션 기반(표준)
    @Bean
    public HttpSessionOAuth2AuthorizationRequestRepository authorizationRequestRepository() {
        return new HttpSessionOAuth2AuthorizationRequestRepository();
    }

    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter() { return new JwtAuthenticationFilter(jwtUtil); }

    @Bean
    public PasswordEncoder passwordEncoder() { return new BCryptPasswordEncoder(); }

    // 정확한 오리진 허용 + 쿠키 전송 허용
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration c = new CorsConfiguration();
        c.setAllowedOrigins(List.of("https://winnerteam.store"));
        c.setAllowedMethods(List.of("GET","POST","PUT","DELETE","OPTIONS"));
        c.setAllowedHeaders(List.of("Authorization","Content-Type","Accept","Origin","X-Requested-With","Cache-Control"));
        c.setAllowCredentials(true);
        UrlBasedCorsConfigurationSource s = new UrlBasedCorsConfigurationSource();
        s.registerCorsConfiguration("/**", c);
        return s;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .httpBasic(b -> b.disable())
                .formLogin(f -> f.disable())
                .cors(c -> c.configurationSource(corsConfigurationSource()))

                // OAuth 핸드셰이크 동안만 세션 허용(인가요청 저장/조회)
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))

                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                        .requestMatchers("/health", "/actuator/health").permitAll()
                        .requestMatchers("/auth/login", "/auth/signup", "/auth/refresh").permitAll()
                        .requestMatchers("/oauth2/**").permitAll() // /oauth2/authorize/* , /oauth2/callback/*
                        .anyRequest().authenticated()
                )

                .oauth2Login(o -> o
                        .authorizationEndpoint(ae -> ae
                                .baseUri("/oauth2/authorize") // 요구사항 경로
                                .authorizationRequestRepository(authorizationRequestRepository())
                        )
                        .redirectionEndpoint(re -> re.baseUri("/oauth2/callback/*"))
                        .userInfoEndpoint(ue -> ue.userService(customOAuth2UserService))
                        .successHandler(oAuth2SuccessHandler)   // JWT 발급/쿠키 세팅
                        .failureHandler(oAuth2FailureHandler)
                )

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

                .addFilterBefore(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
