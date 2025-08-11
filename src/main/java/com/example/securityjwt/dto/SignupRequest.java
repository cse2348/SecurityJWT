package com.example.securityjwt.dto;

import lombok.*;

// 로컬 회원가입 요청 DTO -> 소셜 로그인은 이 DTO를 사용하지 않음
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class SignupRequest {
    private String username; // 로컬 로그인용 (소셜 유저는 null)
    private String password; // 로컬 로그인용 (소셜 유저는 null)
    private String name;     // 공용 표시 이름
    private String email;    // 공용 이메일 (소셜은 null 가능)
}
