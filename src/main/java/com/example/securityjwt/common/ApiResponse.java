package com.example.securityjwt.common;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data // @Getter, @Setter, @ToString, @EqualsAndHashCode, @RequiredArgsConstructor를 한번에 생성해줌 (Lombok)
@NoArgsConstructor
@AllArgsConstructor // 모든 필드를 받는 생성자 생성
public class ApiResponse<T> {
    private boolean success;  // API 요청 성공 여부 (true/false)
    private String message;   // 응답 메시지 (성공, 실패 이유 등)
    private T data;           // 응답 데이터 (제네릭 타입으로 어떤 데이터든 받을 수 있음)

    // 성공 응답
    public static <T> ApiResponse<T> success(T data) {
        return new ApiResponse<>(true, "success", data);
    }

    // 요청이 성공했을 때 사용할 정적 메서드 -> 성공했지만 메시지를 커스텀하고 싶을 때 사용
    public static <T> ApiResponse<T> success(String message, T data) {
        return new ApiResponse<>(true, message, data);
    }

    // 실패 응답 -> 실패 메시지만 전달하고, data는 null로 반환
    public static <T> ApiResponse<T> failure(String message) {
        return new ApiResponse<>(false, message, null);
    }
}
