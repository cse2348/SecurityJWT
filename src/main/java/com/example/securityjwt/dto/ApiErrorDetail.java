package com.example.securityjwt.dto;

import lombok.*;

@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class ApiErrorDetail {
    private String field;
    private String message;
    private Object rejectedValue;
}
