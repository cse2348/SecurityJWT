package com.example.securityjwt.dto;

import com.example.securityjwt.entity.User;
import lombok.*;

// 컨트롤러 응답/리스트 조회(프로젝션) 등에 사용하는 DTO
// 소셜 로그인 사용자는 username이 null일 수 있으므로 name/email도 포함
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserResponse {
    private Long   id;
    private String username; // 로컬 사용자용(소셜은 null 가능)
    private String name;     // 표시 이름(소셜/로컬 공용)
    private String email;    // 이메일(카카오/네이버는 null 가능)

    // 엔티티 -> DTO 변환 헬퍼
    public static UserResponse from(User user) {
        return UserResponse.builder()
                .id(user.getId())
                .username(user.getUsername())
                .name(user.getName())
                .email(user.getEmail())
                .build();
    }

    // Repository 프로젝션과 호환을 위한 추가 생성자 (id, username)
    public UserResponse(Long id, String username) {
        this.id = id;
        this.username = username;
    }
}
