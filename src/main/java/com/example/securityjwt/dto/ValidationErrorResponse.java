package com.example.securityjwt.dto;

import lombok.*;

import java.util.List;

@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class ValidationErrorResponse {
    private String message;                // "요청 값이 올바르지 않습니다."
    private List<ApiErrorDetail> errors;   // 필드별 에러 리스트
}
