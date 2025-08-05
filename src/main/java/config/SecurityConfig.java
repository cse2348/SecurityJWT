package config;

import jwt.JwtAuthenticationFilter;
import jwt.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {


    private final JwtUtil jwtUtil;  // JwtUtil은 Component 등록되어 있음
    private final UserDetailsService userDetailsService;  // UserDetailsService도 Bean 등록되어 있음

    @Bean  // JwtAuthenticationFilter를 직접 Bean으로 등록
    public JwtAuthenticationFilter jwtAuthenticationFilter() {
        return new JwtAuthenticationFilter(jwtUtil, userDetailsService);
    }

    @Bean  // Spring이 관리하는 Bean 등록 (Spring Security 필수 구성)
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf().disable()  // CSRF 보안 비활성화 (JWT는 세션을 사용하지 않기 때문)
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)  // 세션을 사용하지 않는 Stateless 방식
                .and()
                .authorizeHttpRequests()  // 요청 URL 접근 제어 시작
                .requestMatchers("/auth/**").permitAll()  // /auth/** 로 시작하는 요청은 인증 없이 접근 가능 (로그인, 회원가입)
                .anyRequest().authenticated()  // 나머지 요청은 반드시 인증 필요
                .and()
                // UsernamePasswordAuthenticationFilter 앞에 우리가 만든 JwtAuthenticationFilter를 먼저 적용 (토큰 검증용)
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();  // 최종적으로 SecurityFilterChain을 빌드해서 반환
    }

    @Bean  // PasswordEncoder를 Bean으로 등록 (비밀번호 암호화할 때 사용)
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();  // BCrypt 알고리즘을 사용한 암호화 (보안적으로 안전함)
    }
}
