package com.example.securityjwt.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;

/**
 * 회원가입 요청 DTO
 * - 컨트롤러 @PostMapping("/auth/signup") 본문으로 받습니다.
 * - 서버측 유효성 검사(@Valid)와 함께 사용하세요.
 */
@Getter @Setter
public class SignupRequest implements Serializable {

    /**
     * 사용자 ID (로그인용)
     * - 공백 불가
     * - 4~20자, 영문/숫자/언더스코어만 허용(예시 규칙)
     */
    @NotBlank(message = "username은 필수입니다.")
    @Size(min = 4, max = 20, message = "username은 4~20자여야 합니다.")
    @Pattern(regexp = "^[a-zA-Z0-9_]+$", message = "username은 영문/숫자/언더스코어만 가능합니다.")
    private String username;

    /**
     * 비밀번호
     * - 공백 불가
     * - 8~64자
     * - 예시: 영문/숫자/특수문자 조합 권장 (규칙은 팀 정책에 맞게 수정)
     */
    @NotBlank(message = "password는 필수입니다.")
    @Size(min = 8, max = 64, message = "password는 8~64자여야 합니다.")
    private String password;

    /**
     * (선택) 표시용 이름, 별칭 등 확장 필드가 필요하면 추가
     *  예: private String nickname;
     */
}
