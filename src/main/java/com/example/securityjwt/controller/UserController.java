package com.example.securityjwt.controller;

import com.example.securityjwt.common.ApiResponse;
import com.example.securityjwt.dto.UserResponse;
import com.example.securityjwt.entity.User;
import com.example.securityjwt.jwt.JwtAuthenticationFilter;
import com.example.securityjwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

// 보호 API 컨트롤러 ; /user/me : 현재 인증된 사용자 정보 반환
@RestController
@RequestMapping("/user")
@RequiredArgsConstructor
public class UserController {

    private final UserRepository userRepository;

    // 현재 로그인한 사용자 정보 조회
    @GetMapping("/me")
    public ResponseEntity<ApiResponse<UserResponse>> me(Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()) {
            return ResponseEntity.status(401).body(ApiResponse.failure("Unauthorized"));
        }

        Object principal = authentication.getPrincipal();

        // 우리 엔티티(User)가 principal인 경우
        if (principal instanceof User appUser) {
            return ResponseEntity.ok(ApiResponse.success(UserResponse.from(appUser)));
        }

        // Spring Security UserDetails인 경우 (username으로 조회)
        if (principal instanceof UserDetails springUser) {
            return userRepository.findByUsername(springUser.getUsername())
                    .map(UserResponse::from)
                    .map(ApiResponse::success)
                    .map(ResponseEntity::ok)
                    .orElseGet(() -> ResponseEntity.status(404).body(ApiResponse.failure("User not found")));
        }

        // JwtAuthenticationFilter가 세팅하는 JwtPrincipal(userId) 처리
        if (principal instanceof JwtAuthenticationFilter.JwtPrincipal jp) {
            return userRepository.findById(jp.userId())
                    .map(UserResponse::from)
                    .map(ApiResponse::success)
                    .map(ResponseEntity::ok)
                    .orElseGet(() -> ResponseEntity.status(404).body(ApiResponse.failure("User not found")));
        }

        // OAuth2User 처리: email 또는 name으로 조회
        if (principal instanceof org.springframework.security.oauth2.core.user.OAuth2User oAuth2User) {
            String key = (String) oAuth2User.getAttributes().getOrDefault("email", oAuth2User.getName());
            return userRepository.findByUsername(key)
                    .or(() -> userRepository.findByEmail(key))
                    .map(UserResponse::from)
                    .map(ApiResponse::success)
                    .map(ResponseEntity::ok)
                    .orElseGet(() -> ResponseEntity.status(404).body(ApiResponse.failure("User not found")));
        }

        // 기타 미지원 principal 타입
        return ResponseEntity.status(500).body(ApiResponse.failure("Unsupported principal type"));
    }
}
