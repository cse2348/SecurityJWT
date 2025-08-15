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

// 보호 API: 현재 인증된 사용자 정보 반환 컨트롤러
@RestController
@RequestMapping("/user") // 모든 엔드포인트는 /user 하위 경로에 매핑
@RequiredArgsConstructor // final 필드(userRepository) 생성자 주입
public class UserController {

    private final UserRepository userRepository; // 사용자 조회용 JPA 리포지토리

    // 현재 인증된 사용자 정보 조회 (보호 API)
    @GetMapping("/me")
    public ResponseEntity<ApiResponse<UserResponse>> me(Authentication authentication) {
        // 인증 객체가 없거나(is null) 인증되지 않은 경우 인증 실패로 401 반환
        if (authentication == null || !authentication.isAuthenticated()) {
            return ResponseEntity.status(401).body(ApiResponse.failure("Unauthorized"));
        }

        // Spring Security가 세팅한 Authentication에서 principal(실제 사용자 대표 객체) 추출
        Object principal = authentication.getPrincipal();

        // 케이스 1) 우리 애플리케이션의 엔티티(User)가 principal인 경우 (직접 인증 등)
        if (principal instanceof User appUser) {
            // 엔티티를 외부 노출용 DTO(UserResponse)로 변환하여 성공 응답
            return ResponseEntity.ok(ApiResponse.success(UserResponse.from(appUser)));
        }

        // 케이스 2) Spring Security 기본 UserDetails 구현체가 principal인 경우
        if (principal instanceof UserDetails springUser) {
            // username으로 DB 조회 → 엔티티→DTO → ApiResponse → ResponseEntity(200) 순으로 변환
            // Optional 체인을 사용해 null-safe하게 단계별 변환 및 최종 응답 생성
            return userRepository.findByUsername(springUser.getUsername())
                    .map(UserResponse::from)                 // 엔티티 → DTO 변환 (민감정보 차단)
                    .map(ApiResponse::success)               // DTO → 성공 응답 포맷 래핑
                    .map(ResponseEntity::ok)                 // 본문과 함께 200 OK 생성
                    .orElseGet(() ->                         // 조회 실패 시 404로 실패 응답
                            ResponseEntity.status(404).body(ApiResponse.failure("User not found")));
        }

        // 케이스 3) JWT 인증 필터가 주입한 JwtPrincipal(userId 기반)이 principal인 경우
        if (principal instanceof JwtAuthenticationFilter.JwtPrincipal jp) {
            // 토큰에서 추출한 userId로 DB 조회 → 동일한 Optional 변환 체인 적용
            return userRepository.findById(jp.userId())
                    .map(UserResponse::from)
                    .map(ApiResponse::success)
                    .map(ResponseEntity::ok)
                    .orElseGet(() ->
                            ResponseEntity.status(404).body(ApiResponse.failure("User not found")));
        }

        // 케이스 4) OAuth2User(소셜 로그인 사용자)가 principal인 경우
        if (principal instanceof org.springframework.security.oauth2.core.user.OAuth2User oAuth2User) {
            // provider별 userinfo 차이를 흡수: email이 있으면 email, 없으면 name을 조회 키로 사용
            String key = (String) oAuth2User.getAttributes().getOrDefault("email", oAuth2User.getName());

            // username 우선 조회 후 없으면 email로 재시도 → DTO/응답 포맷으로 변환
            return userRepository.findByUsername(key)
                    .or(() -> userRepository.findByEmail(key)) // 대체 키(email)로 재조회
                    .map(UserResponse::from)                   // 엔티티 → DTO
                    .map(ApiResponse::success)                 // DTO → 성공 포맷
                    .map(ResponseEntity::ok)                   // 200 OK
                    .orElseGet(() ->                          // 미존재 시 404
                            ResponseEntity.status(404).body(ApiResponse.failure("User not found")));
        }

        // 위 어떤 타입에도 해당하지 않는 principal → 서버가 처리하지 않는 유형이므로 500 반환
        return ResponseEntity.status(500).body(ApiResponse.failure("Unsupported principal type"));
    }
}
