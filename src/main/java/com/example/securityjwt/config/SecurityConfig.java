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

    private final JwtUtil jwtUtil;  // JwtUtil (Bean 등록되어 있어야 함)
    private final UserDetailsService userDetailsService;  // UserDetailsServiceImpl (Bean 등록되어 있어야 함)

    // JwtAuthenticationFilter를 Bean으로 등록 (의존성 수동 주입)
    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter() {
        return new JwtAuthenticationFilter(jwtUtil, userDetailsService);
    }

    // PasswordEncoder Bean 등록 (BCrypt 사용)
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // SecurityFilterChain 설정 (CORS, CSRF, 세션, 필터 등)
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())  // CSRF 비활성화 (JWT 사용 시)
                .httpBasic(httpBasic -> httpBasic.disable())  // HTTP Basic 인증 비활성화
                .formLogin(form -> form.disable())  // FormLogin 비활성화 (우리는 API로 로그인)
                .cors(cors -> cors.configurationSource(request -> {
                    CorsConfiguration config = new CorsConfiguration();
                    config.setAllowedOriginPatterns(List.of("*"));  // 모든 Origin 허용 (배포 시 특정 도메인으로 제한 가능)
                    config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
                    config.setAllowedHeaders(List.of("*"));
                    config.setAllowCredentials(true);
                    return config;
                }))
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS))  // 세션을 사용하지 않는 Stateless 방식
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()  // Preflight 요청 허용
                        .requestMatchers("/auth/**").permitAll()  // 로그인/회원가입 API 허용
                        .anyRequest().authenticated()  // 그 외 요청은 인증 필요
                )
                .logout(logout -> logout
                        .logoutSuccessHandler((request, response, authentication) -> {
                            response.setStatus(HttpServletResponse.SC_OK);  // 로그아웃 시 200 OK 반환
                        })
                )
                .addFilterBefore(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);  // JWT 필터 등록

        return http.build();
    }
}
