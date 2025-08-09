package com.example.securityjwt.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;

/**
 * 로그인 요청 DTO
 * - 컨트롤러 @PostMapping("/auth/login") 본문으로 받습니다.
 */
@Getter @Setter
public class LoginRequest implements Serializable {

    @NotBlank(message = "username은 필수입니다.")
    @Size(min = 4, max = 20, message = "username은 4~20자여야 합니다.")
    private String username;

    @NotBlank(message = "password는 필수입니다.")
    @Size(min = 8, max = 64, message = "password는 8~64자여야 합니다.")
    private String password;
}
